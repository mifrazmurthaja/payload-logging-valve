/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.support.tomcat.ext.valves;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.coyote.InputBuffer;
import org.apache.coyote.OutputBuffer;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import javax.servlet.ServletException;

/**
 * Logs the full request and response of selected endpoints, for support investigations where the
 * product's own logs do not show what the client actually sent.
 * <p>
 * The valve is a standalone OSGi bundle dropped into {@code repository/components/dropins} and
 * declared in {@code deployment.toml}. It replaces the practice of patching
 * {@code org.wso2.carbon.tomcat.ext}'s {@code RequestCorrelationIdValve}, whose class is part of
 * the kernel and is therefore overwritten by the next WSO2 update.
 * <p>
 * <b>Which requests are logged</b> is driven by {@code includePaths} / {@code excludePaths}
 * instead of a hardcoded URI. The valve is a no-op until {@code includePaths} is set.
 * <p>
 * <b>How the body is captured.</b> The valve decorates the coyote input buffer for the duration
 * of the request and copies each chunk <i>after</i> the delegate has produced it, so the
 * application still reads a complete body. This works for chunked encoding, bodies split across
 * TCP segments and bodies larger than one read, none of which can be relied on when reading
 * Tomcat's internal buffer directly. The original buffer is always restored before the valve
 * returns, because coyote request objects are pooled and reused.
 * <p>
 * Configuration is supplied as XML attributes on the {@code <Valve>} element, which Tomcat's
 * Digester maps onto the setters below.
 * <p>
 * A single valve instance serves every request thread; all per-request state lives in locals.
 */
public class PayloadLoggingValve extends ValveBase {

    private static final String DEFAULT_LOGGER_NAME = PayloadLoggingValve.class.getName();
    private static final String DEFAULT_MASKED_PARAMETERS =
            "client_secret,password,refresh_token,code,assertion,client_assertion,token," +
                    "access_token,id_token,subject_token,actor_token,device_code,session_state," +
                    "requested_token,private_key_jwt";
    private static final String DEFAULT_MASKED_HEADERS = "authorization,proxy-authorization,cookie,set-cookie";
    private static final String CORRELATION_ID_REQUEST_ATTRIBUTE = "org.wso2.request.correlation.MDC";
    private static final String DEFAULT_CORRELATION_ID_KEY = "Correlation-ID";
    private static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";
    private static final String COYOTE_OUTPUT_BUFFER_FIELD = "outputBuffer";
    private static final String SEPARATOR =
            "--------------------------------------------------------------------------------";
    private static final int MIN_BODY_LIMIT = 0;

    private String includePaths;
    private String excludePaths;
    private boolean logRequestHeaders = true;
    private boolean logRequestBody = true;
    private boolean logResponseHeaders = true;
    private boolean logResponseBody = false;
    private boolean fallbackToParameters = true;
    private boolean maskSensitiveData = true;
    private int maxBodySize = 8192;
    private String maskParameters = DEFAULT_MASKED_PARAMETERS;
    private String maskHeaders = DEFAULT_MASKED_HEADERS;
    private String loggerName = DEFAULT_LOGGER_NAME;
    private String correlationIdKey = DEFAULT_CORRELATION_ID_KEY;
    private boolean enabled = true;

    private Log log;
    private PathMatcher includeMatcher;
    private PathMatcher excludeMatcher;
    private PayloadMasker masker;
    private Field coyoteOutputBufferField;

    public PayloadLoggingValve() {

        // This valve neither blocks nor completes the request, so it must not remove async support
        // from the pipeline it is installed in.
        super(true);
    }

    @Override
    protected void initInternal() throws LifecycleException {

        super.initInternal();
        log = LogFactory.getLog(loggerName == null || loggerName.trim().isEmpty()
                ? DEFAULT_LOGGER_NAME : loggerName.trim());
        includeMatcher = PathMatcher.compile(includePaths, message -> log.warn(message));
        excludeMatcher = PathMatcher.compile(excludePaths, message -> log.warn(message));
        masker = maskSensitiveData
                ? PayloadMasker.compile(maskParameters, maskHeaders)
                : PayloadMasker.compile(null, null);
        if (maxBodySize < MIN_BODY_LIMIT) {
            log.warn("maxBodySize " + maxBodySize + " is negative; falling back to 0 (no body captured).");
            maxBodySize = MIN_BODY_LIMIT;
        }
        if (enabled && includeMatcher.isEmpty()) {
            log.warn("PayloadLoggingValve is enabled but includePaths is empty, so no request will be "
                    + "logged. Set includePaths in deployment.toml, for example "
                    + "includePaths = \"/oauth2/token\".");
        } else if (enabled) {
            log.info("PayloadLoggingValve active for paths [" + includePaths + "], maxBodySize=" + maxBodySize
                    + ", masking=" + maskSensitiveData + ", responseBody=" + logResponseBody + ".");
        }
        if (enabled && logResponseBody) {
            resolveCoyoteOutputBufferField();
        }
        if (enabled && !maskSensitiveData) {
            log.warn("PayloadLoggingValve masking is disabled. Credentials and tokens present in the "
                    + "logged endpoints will be written to the log in clear text.");
        }
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        if (!shouldLog(request)) {
            invokeNext(request, response);
            return;
        }

        long startTime = System.currentTimeMillis();
        org.apache.coyote.Request coyoteRequest = request.getCoyoteRequest();
        org.apache.coyote.Response coyoteResponse = response.getCoyoteResponse();
        InputBuffer originalInputBuffer = null;
        OutputBuffer originalOutputBuffer = null;
        CapturingInputBuffer capturedRequest = null;
        CapturingOutputBuffer capturedResponse = null;

        try {
            if (logRequestBody && maxBodySize > 0 && coyoteRequest != null) {
                originalInputBuffer = coyoteRequest.getInputBuffer();
                if (originalInputBuffer != null) {
                    capturedRequest = new CapturingInputBuffer(originalInputBuffer, maxBodySize);
                    coyoteRequest.setInputBuffer(capturedRequest);
                }
            }
            if (logResponseBody && maxBodySize > 0 && coyoteResponse != null) {
                originalOutputBuffer = currentOutputBuffer(coyoteResponse);
                if (originalOutputBuffer != null) {
                    capturedResponse = new CapturingOutputBuffer(originalOutputBuffer, maxBodySize);
                    coyoteResponse.setOutputBuffer(capturedResponse);
                }
            }
            invokeNext(request, response);
        } finally {
            // Restore first and unconditionally: these objects are pooled and reused for the next
            // request on the connection, and an async request keeps reading after this returns.
            if (originalInputBuffer != null) {
                coyoteRequest.setInputBuffer(originalInputBuffer);
            }
            if (originalOutputBuffer != null) {
                coyoteResponse.setOutputBuffer(originalOutputBuffer);
            }
            try {
                logExchange(request, response, capturedRequest, capturedResponse,
                        System.currentTimeMillis() - startTime);
            } catch (Throwable t) {
                log.error("Failed to log the exchange for " + safeUri(request) + ".", t);
            }
        }
    }

    /**
     * Resolves {@code org.apache.coyote.Response.outputBuffer} once, at startup.
     * <p>
     * Unlike the request side, Tomcat 9 exposes {@code setOutputBuffer} but no matching getter, so
     * there is no public way to obtain the buffer a decorator would have to delegate to. This is
     * the single reflective access in the valve: it is resolved once rather than per request, it
     * only reads a field whose type is part of the public {@code OutputBuffer} contract, and if it
     * is unavailable the feature turns itself off instead of failing requests. Response header and
     * status logging do not depend on it.
     */
    private void resolveCoyoteOutputBufferField() {

        try {
            Field field = org.apache.coyote.Response.class.getDeclaredField(COYOTE_OUTPUT_BUFFER_FIELD);
            field.setAccessible(true);
            coyoteOutputBufferField = field;
        } catch (Throwable t) {
            logResponseBody = false;
            log.warn("Response body logging is not available on this Tomcat build because "
                    + "org.apache.coyote.Response." + COYOTE_OUTPUT_BUFFER_FIELD + " could not be "
                    + "accessed. Disabling logResponseBody; everything else still applies.", t);
        }
    }

    private OutputBuffer currentOutputBuffer(org.apache.coyote.Response coyoteResponse) {

        if (coyoteOutputBufferField == null) {
            return null;
        }
        try {
            return (OutputBuffer) coyoteOutputBufferField.get(coyoteResponse);
        } catch (Throwable t) {
            return null;
        }
    }

    private void invokeNext(Request request, Response response) throws IOException, ServletException {

        if (getNext() != null) {
            getNext().invoke(request, response);
        }
    }

    /**
     * The valve sits after {@code ErrorReportValve} and before {@code TenantContextRewriteValve} in
     * the IS 7.2.0 chain, so the URI tested here is the one the client sent, including any
     * {@code /t/<tenant>} prefix.
     */
    private boolean shouldLog(Request request) {

        if (!enabled || includeMatcher == null || includeMatcher.isEmpty()) {
            return false;
        }
        String uri = request.getRequestURI();
        return includeMatcher.matches(uri) && !excludeMatcher.matches(uri);
    }

    private void logExchange(Request request, Response response, CapturingInputBuffer capturedRequest,
                             CapturingOutputBuffer capturedResponse, long timeTakenMillis) {

        if (!log.isInfoEnabled()) {
            return;
        }

        StringBuilder entry = new StringBuilder(4096);
        entry.append(System.lineSeparator()).append(SEPARATOR).append(System.lineSeparator());
        entry.append("HTTP exchange: ").append(request.getMethod()).append(' ').append(safeUri(request));
        String queryString = request.getQueryString();
        if (queryString != null && !queryString.isEmpty()) {
            entry.append('?').append(maskQueryString(queryString));
        }
        entry.append(System.lineSeparator());

        String correlationId = resolveCorrelationId(request);
        if (correlationId != null) {
            entry.append("Correlation-ID : ").append(correlationId).append(System.lineSeparator());
        }
        entry.append("Status         : ").append(response.getStatus()).append(System.lineSeparator());
        entry.append("Time taken     : ").append(timeTakenMillis).append(" ms").append(System.lineSeparator());

        if (logRequestHeaders) {
            entry.append(System.lineSeparator()).append("---- Request headers ----").append(System.lineSeparator());
            appendRequestHeaders(entry, request);
        }
        if (logRequestBody) {
            entry.append(System.lineSeparator()).append("---- Request body ----").append(System.lineSeparator());
            appendRequestBody(entry, request, capturedRequest);
        }
        if (logResponseHeaders) {
            entry.append(System.lineSeparator()).append("---- Response headers ----").append(System.lineSeparator());
            appendResponseHeaders(entry, response);
        }
        if (logResponseBody) {
            entry.append(System.lineSeparator()).append("---- Response body ----").append(System.lineSeparator());
            appendBody(entry, capturedResponse == null ? null : capturedResponse.getCapturedBytes(),
                    capturedResponse != null && capturedResponse.isTruncated(),
                    capturedResponse != null && capturedResponse.isCaptureFailed(),
                    response.getContentType(), response.getCharacterEncoding());
        }
        entry.append(SEPARATOR);

        // One statement per exchange: a multi-line payload split across several log calls
        // interleaves with other threads and becomes unreadable under load.
        log.info(entry.toString());
    }

    private void appendRequestHeaders(StringBuilder entry, Request request) {

        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames == null || !headerNames.hasMoreElements()) {
            entry.append("<none>").append(System.lineSeparator());
            return;
        }
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            Enumeration<String> values = request.getHeaders(name);
            while (values != null && values.hasMoreElements()) {
                entry.append(name).append(": ").append(masker.maskHeader(name, values.nextElement()))
                        .append(System.lineSeparator());
            }
        }
    }

    private void appendResponseHeaders(StringBuilder entry, Response response) {

        boolean any = false;
        for (String name : response.getHeaderNames()) {
            for (String value : response.getHeaders(name)) {
                entry.append(name).append(": ").append(masker.maskHeader(name, value))
                        .append(System.lineSeparator());
                any = true;
            }
        }
        if (!any) {
            entry.append("<none>").append(System.lineSeparator());
        }
    }

    /**
     * Prints the captured request body. When the application never read the body — an early
     * rejection, for instance — nothing was captured; in that case, and only for a form-encoded
     * POST, the parsed parameter map is printed instead so the exchange is still diagnosable.
     */
    private void appendRequestBody(StringBuilder entry, Request request,
                                   CapturingInputBuffer capturedRequest) {

        byte[] body = capturedRequest == null ? null : capturedRequest.getCapturedBytes();
        if (body != null && body.length > 0) {
            appendBody(entry, body, capturedRequest.isTruncated(), capturedRequest.isCaptureFailed(),
                    request.getContentType(), request.getCharacterEncoding());
            return;
        }
        if (fallbackToParameters && isFormEncoded(request.getContentType())) {
            appendParameters(entry, request);
            return;
        }
        if (capturedRequest == null) {
            entry.append("<not captured: request body logging is off or the input buffer was unavailable>")
                    .append(System.lineSeparator());
        } else {
            entry.append("<empty: the application did not read a request body>")
                    .append(System.lineSeparator());
        }
    }

    /**
     * Last-resort view of a form body that was never read off the wire by the application. Reading
     * the parameter map here is safe: the response has already been produced, so parsing cannot
     * take the body away from anything that still needs it.
     */
    private void appendParameters(StringBuilder entry, Request request) {

        try {
            Map<String, String[]> parameters = request.getParameterMap();
            if (parameters == null || parameters.isEmpty()) {
                entry.append("<empty: the application did not read a request body>")
                        .append(System.lineSeparator());
                return;
            }
            entry.append("<body not read by the application; showing parsed parameters, "
                    + "which also include query parameters>").append(System.lineSeparator());
            for (Map.Entry<String, String[]> parameter : parameters.entrySet()) {
                for (String value : parameter.getValue()) {
                    entry.append(parameter.getKey()).append('=')
                            .append(masker.maskParameter(parameter.getKey(), value))
                            .append(System.lineSeparator());
                }
            }
        } catch (Throwable t) {
            entry.append("<parameters unavailable: ").append(t.getClass().getSimpleName()).append('>')
                    .append(System.lineSeparator());
        }
    }

    private void appendBody(StringBuilder entry, byte[] body, boolean truncated, boolean captureFailed,
                            String contentType, String characterEncoding) {

        if (body == null || body.length == 0) {
            entry.append("<empty>").append(System.lineSeparator());
            return;
        }
        String decoded = new String(body, resolveCharset(characterEncoding));
        entry.append(maskBody(decoded, contentType));
        if (truncated) {
            entry.append(System.lineSeparator())
                    .append("<truncated at maxBodySize=").append(maxBodySize).append(" bytes>");
        }
        if (captureFailed) {
            entry.append(System.lineSeparator()).append("<capture incomplete: a chunk could not be copied>");
        }
        entry.append(System.lineSeparator());
    }

    private String maskBody(String body, String contentType) {

        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ENGLISH);
        if (type.contains(FORM_CONTENT_TYPE)) {
            return masker.maskFormBody(body);
        }
        if (type.contains("json")) {
            return masker.maskJsonBody(body);
        }
        return body;
    }

    private String maskQueryString(String queryString) {

        return masker.maskFormBody(queryString);
    }

    private static boolean isFormEncoded(String contentType) {

        return contentType != null && contentType.toLowerCase(Locale.ENGLISH).contains(FORM_CONTENT_TYPE);
    }

    private static Charset resolveCharset(String characterEncoding) {

        if (characterEncoding == null || characterEncoding.isEmpty()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(characterEncoding);
        } catch (IllegalCharsetNameException | UnsupportedCharsetException e) {
            return StandardCharsets.UTF_8;
        }
    }

    /**
     * Reads the correlation id that {@code RequestCorrelationIdValve} publishes as a request
     * attribute earlier in the chain, so this entry can be tied to the correlation logs.
     */
    private String resolveCorrelationId(Request request) {

        try {
            Object attribute = request.getAttribute(CORRELATION_ID_REQUEST_ATTRIBUTE);
            if (attribute instanceof Map) {
                Object value = ((Map<?, ?>) attribute).get(correlationIdKey);
                return value == null ? null : value.toString();
            }
        } catch (Throwable t) {
            // The correlation id is a convenience; never let its absence cost us the log entry.
        }
        return null;
    }

    private static String safeUri(Request request) {

        String uri = request.getRequestURI();
        return uri == null ? "<unknown>" : uri;
    }

    // ---------------------------------------------------------------------------------------
    // Setters. Tomcat's Digester calls these for each XML attribute on the <Valve> element.
    // ---------------------------------------------------------------------------------------

    /**
     * @param includePaths comma separated paths to log. A plain value matches by substring, a
     *                     value containing {@code *} matches as a wildcard, and a value prefixed
     *                     with {@code regex:} is a regular expression. Empty means log nothing.
     */
    public void setIncludePaths(String includePaths) {

        this.includePaths = includePaths;
    }

    /**
     * @param excludePaths comma separated paths to skip, in the same syntax as includePaths.
     *                     Applied after includePaths.
     */
    public void setExcludePaths(String excludePaths) {

        this.excludePaths = excludePaths;
    }

    /**
     * @param logRequestHeaders whether request headers are logged. Default {@code true}.
     */
    public void setLogRequestHeaders(boolean logRequestHeaders) {

        this.logRequestHeaders = logRequestHeaders;
    }

    /**
     * @param logRequestBody whether the request body is captured and logged. Default {@code true}.
     */
    public void setLogRequestBody(boolean logRequestBody) {

        this.logRequestBody = logRequestBody;
    }

    /**
     * @param logResponseHeaders whether response headers are logged. Default {@code true}.
     */
    public void setLogResponseHeaders(boolean logResponseHeaders) {

        this.logResponseHeaders = logResponseHeaders;
    }

    /**
     * @param logResponseBody whether the response body is captured and logged. Default
     *                        {@code false}: on the token endpoint the response body is the issued
     *                        token.
     */
    public void setLogResponseBody(boolean logResponseBody) {

        this.logResponseBody = logResponseBody;
    }

    /**
     * @param fallbackToParameters whether to print the parsed parameter map when a form-encoded
     *                             body was never read by the application. Default {@code true}.
     */
    public void setFallbackToParameters(boolean fallbackToParameters) {

        this.fallbackToParameters = fallbackToParameters;
    }

    /**
     * @param maskSensitiveData whether credentials and tokens are redacted. Default {@code true}.
     */
    public void setMaskSensitiveData(boolean maskSensitiveData) {

        this.maskSensitiveData = maskSensitiveData;
    }

    /**
     * @param maxBodySize maximum number of body bytes retained per direction. Default 8192.
     */
    public void setMaxBodySize(int maxBodySize) {

        this.maxBodySize = maxBodySize;
    }

    /**
     * @param maskParameters comma separated form, query and JSON field names to redact.
     */
    public void setMaskParameters(String maskParameters) {

        this.maskParameters = maskParameters;
    }

    /**
     * @param maskHeaders comma separated header names to redact.
     */
    public void setMaskHeaders(String maskHeaders) {

        this.maskHeaders = maskHeaders;
    }

    /**
     * @param loggerName the commons-logging category to write to. Set this to route the payloads
     *                   to their own log4j2 appender instead of wso2carbon.log.
     */
    public void setLoggerName(String loggerName) {

        this.loggerName = loggerName;
    }

    /**
     * @param correlationIdKey key to read from the correlation id map published by
     *                         {@code RequestCorrelationIdValve}. Default {@code Correlation-ID}.
     */
    public void setCorrelationIdKey(String correlationIdKey) {

        this.correlationIdKey = correlationIdKey;
    }

    /**
     * @param enabled master switch. Default {@code true}; set to {@code false} to leave the valve
     *                declared but inert.
     */
    public void setEnabled(boolean enabled) {

        this.enabled = enabled;
    }
}
