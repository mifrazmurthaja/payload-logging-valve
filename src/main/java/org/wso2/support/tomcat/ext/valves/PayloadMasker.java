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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Redacts secrets before they reach the log file.
 * <p>
 * The token endpoint carries {@code client_secret}, {@code password}, {@code code},
 * {@code refresh_token} and an {@code Authorization: Basic} header in the clear, and the response
 * carries the issued tokens. Writing those verbatim moves a credential from a TLS-protected
 * request into a log file that is typically shipped off-box, so masking is on by default and the
 * name lists are configurable rather than optional.
 * <p>
 * Instances are immutable and safe to share across request threads.
 */
final class PayloadMasker {

    static final String MASK = "***MASKED***";

    private final Set<String> maskedParameters;
    private final Set<String> maskedHeaders;
    private final Pattern jsonFieldPattern;

    private PayloadMasker(Set<String> maskedParameters, Set<String> maskedHeaders) {

        this.maskedParameters = maskedParameters;
        this.maskedHeaders = maskedHeaders;
        this.jsonFieldPattern = buildJsonFieldPattern(maskedParameters);
    }

    /**
     * @param parameterCsv comma separated form/query/JSON field names to redact
     * @param headerCsv    comma separated header names to redact
     * @return a masker over the lower-cased name sets
     */
    static PayloadMasker compile(String parameterCsv, String headerCsv) {

        return new PayloadMasker(toLowerCaseSet(parameterCsv), toLowerCaseSet(headerCsv));
    }

    /**
     * Redacts a header value. For a scheme-prefixed value such as {@code Basic dXNlcjpwYXNz} the
     * scheme is preserved, because knowing whether the client authenticated with Basic, Bearer or
     * a client assertion is usually the point of reading the log.
     *
     * @param name  header name
     * @param value header value
     * @return the value, redacted when the header is in the masked set
     */
    String maskHeader(String name, String value) {

        if (name == null || value == null || !maskedHeaders.contains(name.toLowerCase(Locale.ENGLISH))) {
            return value;
        }
        int separator = value.indexOf(' ');
        if (separator > 0) {
            return value.substring(0, separator) + " " + MASK;
        }
        return MASK;
    }

    /**
     * @param name  parameter name
     * @param value parameter value
     * @return the value, redacted when the parameter is in the masked set
     */
    String maskParameter(String name, String value) {

        if (name == null || !maskedParameters.contains(name.toLowerCase(Locale.ENGLISH))) {
            return value;
        }
        return MASK;
    }

    /**
     * Redacts an {@code application/x-www-form-urlencoded} body in place, preserving the original
     * wire encoding of everything that is not masked. Names are URL-decoded only to test them
     * against the masked set; the surviving pairs are emitted exactly as they were received.
     *
     * @param body raw form-encoded body
     * @return the body with masked values replaced
     */
    String maskFormBody(String body) {

        if (body == null || body.isEmpty()) {
            return body;
        }
        StringBuilder masked = new StringBuilder(body.length());
        for (String pair : body.split("&", -1)) {
            if (masked.length() > 0) {
                masked.append('&');
            }
            int equals = pair.indexOf('=');
            if (equals < 0) {
                masked.append(pair);
                continue;
            }
            String rawName = pair.substring(0, equals);
            if (maskedParameters.contains(urlDecode(rawName).toLowerCase(Locale.ENGLISH))) {
                masked.append(rawName).append('=').append(MASK);
            } else {
                masked.append(pair);
            }
        }
        return masked.toString();
    }

    /**
     * Redacts string-valued JSON fields whose name is in the masked set. This is a textual pass
     * rather than a parse: the body is logged as received even when it is malformed, which is
     * often exactly the payload worth looking at.
     *
     * @param body raw JSON body
     * @return the body with masked field values replaced
     */
    String maskJsonBody(String body) {

        if (body == null || body.isEmpty() || jsonFieldPattern == null) {
            return body;
        }
        Matcher matcher = jsonFieldPattern.matcher(body);
        StringBuffer masked = new StringBuffer(body.length());
        while (matcher.find()) {
            matcher.appendReplacement(masked, Matcher.quoteReplacement(matcher.group(1) + MASK + "\""));
        }
        matcher.appendTail(masked);
        return masked.toString();
    }

    /**
     * Builds a pattern matching {@code "name" : "value"} for any masked name, capturing everything
     * up to and including the opening quote of the value so the replacement can keep it.
     */
    private static Pattern buildJsonFieldPattern(Set<String> names) {

        if (names.isEmpty()) {
            return null;
        }
        StringBuilder alternation = new StringBuilder();
        for (String name : names) {
            if (alternation.length() > 0) {
                alternation.append('|');
            }
            alternation.append(Pattern.quote(name));
        }
        return Pattern.compile("(\"(?:" + alternation + ")\"\\s*:\\s*\")[^\"]*\"",
                Pattern.CASE_INSENSITIVE);
    }

    private static Set<String> toLowerCaseSet(String csv) {

        if (csv == null) {
            return Collections.emptySet();
        }
        Set<String> values = new HashSet<>();
        for (String rawEntry : csv.split(",")) {
            String entry = rawEntry.trim();
            if (!entry.isEmpty()) {
                values.add(entry.toLowerCase(Locale.ENGLISH));
            }
        }
        return Collections.unmodifiableSet(values);
    }

    private static String urlDecode(String value) {

        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return value;
        }
    }
}
