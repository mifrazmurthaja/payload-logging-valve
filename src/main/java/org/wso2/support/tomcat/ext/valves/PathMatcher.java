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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Matches a request URI against a comma separated list of path patterns.
 * <p>
 * Three pattern flavours are supported:
 * <ul>
 *     <li><b>plain</b> &mdash; {@code /oauth2/token}: matches when the URI <i>contains</i> the
 *         pattern. This tolerates the tenant qualified form of the URI
 *         ({@code /t/example.com/oauth2/token}), which is what this valve sees, because the
 *         valve runs before {@code TenantContextRewriteValve} in the IS 7.2.0 valve chain.</li>
 *     <li><b>wildcard</b> &mdash; {@code /oauth2/*}: {@code *} matches any run of characters,
 *         anchored to the whole URI.</li>
 *     <li><b>regex</b> &mdash; {@code regex:^/t/[^/]+/oauth2/token$}: the remainder is compiled
 *         as a {@link Pattern} and anchored with {@link java.util.regex.Matcher#matches()}.</li>
 * </ul>
 * Instances are immutable and safe to share across request threads.
 */
final class PathMatcher {

    private static final String REGEX_PREFIX = "regex:";

    private final List<String> literals = new ArrayList<>();
    private final List<Pattern> patterns = new ArrayList<>();

    private PathMatcher() {

    }

    /**
     * Compiles a comma separated pattern list. Blank entries are ignored. Entries that declare
     * themselves as regular expressions but fail to compile are reported through {@code onError}
     * and skipped, so that one bad pattern cannot stop the server from starting.
     *
     * @param csv     comma separated pattern list, may be {@code null} or empty
     * @param onError callback invoked with a human readable message for each unusable pattern
     * @return a matcher; {@link #isEmpty()} is {@code true} when nothing usable was configured
     */
    static PathMatcher compile(String csv, ErrorReporter onError) {

        PathMatcher matcher = new PathMatcher();
        if (csv == null) {
            return matcher;
        }
        for (String rawEntry : csv.split(",")) {
            String entry = rawEntry.trim();
            if (entry.isEmpty()) {
                continue;
            }
            if (entry.regionMatches(true, 0, REGEX_PREFIX, 0, REGEX_PREFIX.length())) {
                String regex = entry.substring(REGEX_PREFIX.length()).trim();
                try {
                    matcher.patterns.add(Pattern.compile(regex));
                } catch (PatternSyntaxException e) {
                    onError.report("Ignoring unparsable regex path pattern '" + regex + "': " + e.getMessage());
                }
            } else if (entry.indexOf('*') >= 0) {
                matcher.patterns.add(Pattern.compile(wildcardToRegex(entry)));
            } else {
                matcher.literals.add(entry);
            }
        }
        return matcher;
    }

    /**
     * @return {@code true} when no usable pattern was configured
     */
    boolean isEmpty() {

        return literals.isEmpty() && patterns.isEmpty();
    }

    /**
     * @param uri request URI to test, may be {@code null}
     * @return {@code true} when at least one configured pattern matches
     */
    boolean matches(String uri) {

        if (uri == null) {
            return false;
        }
        for (String literal : literals) {
            if (uri.contains(literal)) {
                return true;
            }
        }
        for (Pattern pattern : patterns) {
            if (pattern.matcher(uri).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Translates a {@code *} wildcard pattern into an anchored regular expression, quoting every
     * other character so that dots and slashes in a URI are never treated as regex metacharacters.
     */
    private static String wildcardToRegex(String wildcard) {

        StringBuilder regex = new StringBuilder(wildcard.length() + 16);
        int literalStart = 0;
        for (int i = 0; i < wildcard.length(); i++) {
            if (wildcard.charAt(i) == '*') {
                if (i > literalStart) {
                    regex.append(Pattern.quote(wildcard.substring(literalStart, i)));
                }
                regex.append(".*");
                literalStart = i + 1;
            }
        }
        if (literalStart < wildcard.length()) {
            regex.append(Pattern.quote(wildcard.substring(literalStart)));
        }
        return regex.toString();
    }

    /**
     * Sink for configuration problems found while compiling patterns.
     */
    interface ErrorReporter {

        void report(String message);
    }
}
