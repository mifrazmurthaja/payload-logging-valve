# Payload Logging Valve — WSO2 Identity Server 7.2.0

A standalone Tomcat valve that logs the full request (and optionally the response) of
**configurable** endpoints.

Nothing in the product is patched or replaced. The valve is its own OSGi bundle in
`repository/components/dropins`, wired into the valve chain through the supported
`[catalina.valves.*.properties]` configuration in `deployment.toml`.

| Branch / tag | WSO2 Identity Server |
| --- | --- |
| `main` | 7.3.0 |
| [`7.2`](../../releases/tag/7.2) | 7.2.0 |

---

## 1. Build

```bash
cd payload-logging-valve
mvn clean install
```

Produces `target/org.wso2.support.tomcat.ext.payload.valve-1.0.0.jar`.

Requires JDK 8 or 11 and Maven 3.6+. The Tomcat dependency is `provided` and pinned to
`9.0.102`, matching `tomcat_9.0.102.wso2v1.jar` shipped in IS 7.2.0.

## 2. Deploy

1. Copy the JAR to `<IS_HOME>/repository/components/dropins/`.
2. Add the valve to `<IS_HOME>/repository/conf/deployment.toml` (see below).
3. Restart the server.

> The bundle **must export** `org.wso2.support.tomcat.ext.valves`, which the supplied `pom.xml`
> does. `catalina-server.xml` is parsed by a Digester running inside the `tomcat` OSGi bundle,
> which finds valve classes through its `DynamicImport-Package: *` header; a dynamic import can
> only bind to a package that some bundle exports. Without the export the server starts and the
> valve silently fails to instantiate.

## 3. Configure

```toml
[catalina.valves.payload_logger.properties]
className    = "org.wso2.support.tomcat.ext.valves.PayloadLoggingValve"
includePaths = "/oauth2/token"
```

`payload_logger` is just a name — use a different one per valve if you add more than one. Every
key under `properties` is rendered verbatim as an XML attribute on a `<Valve>` element in
`<IS_HOME>/repository/conf/tomcat/catalina-server.xml`, so the attribute names below are the
TOML keys.

### Attributes

| Attribute | Default | Description |
| --- | --- | --- |
| `className` | — | Required. `org.wso2.support.tomcat.ext.valves.PayloadLoggingValve`. |
| `includePaths` | *(empty)* | Comma-separated paths to log. **Empty means nothing is logged.** |
| `excludePaths` | *(empty)* | Comma-separated paths to skip; applied after `includePaths`. |
| `logRequestHeaders` | `true` | Log request headers. |
| `logRequestBody` | `true` | Capture and log the request body. |
| `logResponseHeaders` | `true` | Log response headers. |
| `logResponseBody` | `false` | Capture and log the response body. Off by default: on the token endpoint the response body *is* the issued token. |
| `fallbackToParameters` | `true` | If a form-encoded body was never read by the application, log the parsed parameter map instead. |
| `maskSensitiveData` | `true` | Redact credentials and tokens. |
| `maskParameters` | `client_secret,password,refresh_token,code,assertion,client_assertion,token,access_token,id_token,subject_token,actor_token,device_code,session_state,requested_token,private_key_jwt` | Form, query and JSON field names to redact. |
| `maskHeaders` | `authorization,proxy-authorization,cookie,set-cookie` | Header names to redact. For `Authorization` the scheme is kept (`Basic ***MASKED***`). |
| `maxBodySize` | `8192` | Maximum bytes retained per direction. Bodies beyond this are marked `<truncated>`. |
| `loggerName` | `org.wso2.support.tomcat.ext.valves.PayloadLoggingValve` | Log category. Change it to route payloads to a dedicated appender. |
| `correlationIdKey` | `Correlation-ID` | Key read from the correlation map published by `RequestCorrelationIdValve`. |
| `enabled` | `true` | Master switch; `false` leaves the valve declared but inert. |

### Path syntax

| Form | Example | Matches |
| --- | --- | --- |
| Plain | `/oauth2/token` | Any URI **containing** the value — including `/t/example.com/oauth2/token`. |
| Wildcard | `/oauth2/*` | `*` matches any run of characters, anchored to the whole URI. Everything else is matched literally, so dots are safe. |
| Regex | `regex:^(/t/[^/]+)?/oauth2/token$` | Anchored `Pattern.matches`. |

The valve runs **before** `TenantContextRewriteValve`, so the URI it sees still carries any
`/t/<tenant>` prefix. The plain form tolerates that; an anchored wildcard or regex must account
for it.

> A regex cannot contain a comma — the attribute is split on commas first. Use a wildcard or a
> bounded quantifier-free alternative, or declare two valves.

### Examples

Token endpoint, request only:

```toml
[catalina.valves.payload_logger.properties]
className    = "org.wso2.support.tomcat.ext.valves.PayloadLoggingValve"
includePaths = "/oauth2/token"
```

Several OAuth endpoints, excluding one, with response bodies, to a dedicated logger:

```toml
[catalina.valves.payload_logger.properties]
className       = "org.wso2.support.tomcat.ext.valves.PayloadLoggingValve"
includePaths    = "/oauth2/token,/oauth2/revoke,/oauth2/introspect"
excludePaths    = "/oauth2/introspect"
logResponseBody = "true"
maxBodySize     = "16384"
loggerName      = "PAYLOAD_LOG"
```

SCIM2 user provisioning (JSON bodies are masked by field name):

```toml
[catalina.valves.payload_logger.properties]
className    = "org.wso2.support.tomcat.ext.valves.PayloadLoggingValve"
includePaths = "/scim2/Users*"
```

> TOML booleans and integers work as bare values too (`logResponseBody = true`), but quoting them
> is safer: the value is copied straight into the XML attribute either way.

## 4. Routing to a dedicated log file (optional)

With `loggerName = "PAYLOAD_LOG"`, add to `<IS_HOME>/repository/conf/log4j2.properties`:

```properties
# add PAYLOAD_LOG to both lists
appenders = ..., PAYLOAD_LOG
loggers   = ..., PAYLOAD_LOG

appender.PAYLOAD_LOG.type = RollingFile
appender.PAYLOAD_LOG.name = PAYLOAD_LOG
appender.PAYLOAD_LOG.fileName = ${sys:carbon.home}/repository/logs/payload.log
appender.PAYLOAD_LOG.filePattern = ${sys:carbon.home}/repository/logs/payload-%d{MM-dd-yyyy}.log
appender.PAYLOAD_LOG.layout.type = PatternLayout
appender.PAYLOAD_LOG.layout.pattern = [%d] %5p {%c} - %m%ex%n
appender.PAYLOAD_LOG.policies.type = Policies
appender.PAYLOAD_LOG.policies.time.type = TimeBasedTriggeringPolicy
appender.PAYLOAD_LOG.policies.time.interval = 1
appender.PAYLOAD_LOG.policies.size.type = SizeBasedTriggeringPolicy
appender.PAYLOAD_LOG.policies.size.size = 50MB
appender.PAYLOAD_LOG.strategy.type = DefaultRolloverStrategy
appender.PAYLOAD_LOG.strategy.max = 10

logger.PAYLOAD_LOG.name = PAYLOAD_LOG
logger.PAYLOAD_LOG.level = INFO
logger.PAYLOAD_LOG.appenderRef.PAYLOAD_LOG.ref = PAYLOAD_LOG
logger.PAYLOAD_LOG.additivity = false
```

Setting the level above `INFO` disables the valve's output without a restart.

## 5. Sample output

```
--------------------------------------------------------------------------------
HTTP exchange: POST /oauth2/token
Correlation-ID : 6f0a1f7c-6c3a-4a4e-9a0e-0e1d2b3c4d5e
Status         : 400
Time taken     : 37 ms

---- Request headers ----
host: localhost:9443
authorization: Basic ***MASKED***
content-type: application/x-www-form-urlencoded
content-length: 61

---- Request body ----
grant_type=password&username=alice&password=***MASKED***&scope=openid

---- Response headers ----
Content-Type: application/json
Cache-Control: no-store
--------------------------------------------------------------------------------
```

## 6. Design notes

**Body capture does not read Tomcat's internal buffer.** The obvious way to get at a request
body from a valve is to reach into `coyoteRequest.getInputBuffer()` by reflection and read
whatever bytes are sitting in `Http11InputBuffer`'s `ByteBuffer` before the request is
dispatched. That works for a small form POST whose body arrives in the same socket read as the
headers — `/oauth2/token` usually does — but it returns nothing or a partial body when the body
is chunked, larger than one read, or split across TCP segments, and it yields nothing at all on
any connector whose input buffer exposes none of `getByteChunk` / `getByteBuffer` /
`getReadBuffer`.

This valve instead installs a pass-through decorator on the coyote input buffer for the duration
of the request and copies each chunk *after* the delegate produces it. The application still reads a
complete, untouched body; the capture is correct for chunked and multi-read bodies; and the
original buffer is restored in a `finally` block, because coyote request objects are pooled and
reused for the next request on the connection.

The consequence is that the body is logged **as the application reads it**. If the request is
rejected before anything reads the body, the capture is empty — `fallbackToParameters` covers the
common form-encoded case by printing the parsed parameters instead.

**Secrets are redacted by default.** Logging `Authorization: Basic …`, `client_secret` and
`password` verbatim moves a live credential out of the TLS-protected request and into a log file
that is usually shipped off-box. Masking is therefore on by default and the name lists are
configurable. `maskSensitiveData = "false"` turns it off; the valve logs a warning at startup
when you do.

## 7. Notes and limitations

- **Cost.** Only matched paths are instrumented; everything else takes one string match and the
  original code path. For matched requests, expect one extra copy of up to `maxBodySize` bytes
  per direction and a multi-kilobyte log line. This is a diagnostic tool — scope `includePaths`
  narrowly and turn it off when the investigation is over.
- **Valve position.** The `[catalina.valves.*]` entries render near the end of the chain, after
  `ErrorReportValve` and before `TenantContextRewriteValve`. The valve still wraps the servlet
  invocation, so request, status, headers and timing are all complete.
- **Async requests.** The status and body captured at the point the valve returns may be
  incomplete for a request that has gone async. IS's OAuth2 endpoints are synchronous.
- **Response body capture** is the one place reflection is used: Tomcat 9 exposes
  `org.apache.coyote.Response.setOutputBuffer` but no matching getter, so there is no public way
  to reach the buffer a decorator must delegate to. The field is resolved once at startup, and if
  it cannot be accessed the valve logs a warning and disables `logResponseBody` only — status and
  response headers are unaffected. `logResponseBody = "false"` (the default) uses no reflection
  at all.
- **HTTP/2 and AJP** use different processors. The request-side capture is connector-agnostic
  because it decorates `org.apache.coyote.Request`'s buffer rather than a specific
  implementation, but it has only been exercised on the HTTP/1.1 connector.
- Logging happens at `INFO` on the configured category, as one statement per exchange, so
  multi-line payloads do not interleave across threads.

### Verified on

Built and run against a clean **WSO2 Identity Server 7.2.0** pack (Tomcat 9.0.102, carbon-kernel
4.10.101, JDK 11). The bundle resolved from `dropins`, the Digester instantiated the valve and
applied every attribute, and `POST /oauth2/token` was logged correctly for a `Content-Length`
body, a body exceeding `maxBodySize` (truncation marker emitted) and a `Transfer-Encoding:
chunked` body. `Authorization`, `password`, `client_secret` and `refresh_token` were redacted;
`/oauth2/jwks` was not logged; and IS parsed the request body normally in every case, confirming
the tee does not consume it.

## 8. Layout

```
payload-logging-valve/
├── pom.xml
├── README.md
└── src/main/java/org/wso2/support/tomcat/ext/valves/
    ├── PayloadLoggingValve.java     the valve: config, matching, orchestration, log entry
    ├── CapturingInputBuffer.java    request-body tee
    ├── CapturingOutputBuffer.java   response-body tee
    ├── PathMatcher.java             substring / wildcard / regex path matching
    └── PayloadMasker.java           header, form, query and JSON redaction
```
