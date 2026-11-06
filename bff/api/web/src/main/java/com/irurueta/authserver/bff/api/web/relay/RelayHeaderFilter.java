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
package com.irurueta.authserver.bff.api.web.relay;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

/**
 * Decides which headers cross the relay. Inbound, only the headers of an allow-list are forwarded, so the session
 * {@code Cookie}, the {@code Authorization} header and the CSRF headers of the browser never reach the resource
 * server. Outbound, every header is forwarded except {@code Set-Cookie} (the resource server must not set cookies on
 * the BFF origin), {@code WWW-Authenticate} (the bearer token is an internal matter) and the hop-by-hop headers.
 */
@Component
public class RelayHeaderFilter {

    /** Lower-case names of the request headers forwarded to the resource server. */
    private static final Set<String> ALLOWED_REQUEST_HEADERS = Set.of("accept", "accept-language", "content-type",
            "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "if-range", "range");

    /** Lower-case names of the response headers that are never returned to the browser. */
    private static final Set<String> BLOCKED_RESPONSE_HEADERS = Set.of("set-cookie", "set-cookie2",
            "www-authenticate", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
            "trailer", "transfer-encoding", "upgrade");

    /**
     * Copies the allowed headers of the inbound request.
     *
     * @param request the request of the browser.
     * @param target  the headers of the request to the resource server.
     */
    public void copyRequestHeaders(final HttpServletRequest request, final HttpHeaders target) {
        for (final var name : Collections.list(request.getHeaderNames())) {
            if (ALLOWED_REQUEST_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                target.addAll(name, Collections.list(request.getHeaders(name)));
            }
        }
    }

    /**
     * Copies the headers of the resource server's response that may reach the browser.
     *
     * @param source   the headers of the response of the resource server.
     * @param response the response to the browser.
     */
    public void copyResponseHeaders(final HttpHeaders source, final HttpServletResponse response) {
        source.forEach((name, values) -> {
            if (!BLOCKED_RESPONSE_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                values.forEach(value -> response.addHeader(name, value));
            }
        });
    }
}
