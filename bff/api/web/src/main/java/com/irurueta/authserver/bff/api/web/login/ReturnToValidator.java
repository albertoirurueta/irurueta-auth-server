/*
 * Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.irurueta.authserver.bff.api.web.login;

import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

// tag::bff-return-to-validator[]
/**
 * Decides whether a {@code returnTo} value asked by the browser is a safe place to send it back to after the login.
 * An open redirect would let a crafted link bounce a freshly signed-in user to a hostile site, so only a relative
 * path, listed in {@code bff.login.allowed-return-paths}, is ever accepted.
 */
@Component
@RequiredArgsConstructor
@EnableConfigurationProperties(BffLoginProperties.class)
public class ReturnToValidator {

    /** An URL scheme at the start (for example {@code javascript:}), also when hidden in the first segment. */
    private static final Pattern SCHEME = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*:");

    /** Allowed paths. */
    private final BffLoginProperties properties;

    /**
     * Checks a {@code returnTo} value.
     *
     * @param returnTo the value to check; may be {@code null}.
     * @return {@code true} when it is a relative path allowed by the configuration, without scheme, authority,
     *         backslash, dot segment or control character.
     */
    public boolean isAllowed(final String returnTo) {
        if (returnTo == null || !returnTo.startsWith("/") || returnTo.startsWith("//")
                || SCHEME.matcher(returnTo).find() || returnTo.indexOf('\\') >= 0
                || returnTo.chars().anyMatch(Character::isISOControl)) {
            return false;
        }
        final var path = pathOf(returnTo);
        if (path.contains("/../") || path.endsWith("/..") || path.contains("/./")
                || path.contains("%")) {
            return false;
        }
        return properties.allowedReturnPaths().stream()
                .anyMatch(allowed -> path.equals(allowed) || isPrefix(allowed) && path.startsWith(allowed));
    }

    /**
     * Tells whether an allow-list entry covers the paths below it: it ends with {@code /} but is not the root, which
     * would allow every path.
     *
     * @param allowed an allow-list entry.
     * @return {@code true} for a prefix entry such as {@code /orders/}.
     */
    private static boolean isPrefix(final String allowed) {
        return allowed.length() > 1 && allowed.endsWith("/");
    }

    /**
     * Strips the query string and the fragment.
     *
     * @param returnTo a value starting with {@code /}.
     * @return its path.
     */
    private static String pathOf(final String returnTo) {
        var end = returnTo.length();
        final var query = returnTo.indexOf('?');
        if (query >= 0) {
            end = query;
        }
        final var fragment = returnTo.indexOf('#');
        if (fragment >= 0 && fragment < end) {
            end = fragment;
        }
        return returnTo.substring(0, end);
    }
}
// end::bff-return-to-validator[]
