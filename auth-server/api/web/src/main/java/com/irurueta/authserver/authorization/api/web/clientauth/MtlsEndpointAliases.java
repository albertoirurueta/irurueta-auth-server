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
package com.irurueta.authserver.authorization.api.web.clientauth;

import com.irurueta.authserver.authorization.api.web.x509.X509Properties;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Builds the {@code mtls_endpoint_aliases} metadata claim of RFC 8705 (section 5): the addresses of the endpoints
 * that authenticate clients on the dedicated TLS port, the issuer's host with {@code authserver.x509.port}. Nothing
 * is added while that port is not configured.
 */
@RequiredArgsConstructor
public class MtlsEndpointAliases {

    /** Name of the metadata claim. */
    public static final String CLAIM = "mtls_endpoint_aliases";

    /** Scheme of the TLS port. */
    private static final String HTTPS = "https";

    /** Settings of the X.509 sign-in and its dedicated port. */
    private final X509Properties x509Properties;

    /** Paths of the protocol endpoints and the configured issuer. */
    private final AuthorizationServerSettings settings;

    /**
     * Adds the claim to a metadata document, when the TLS port is configured.
     *
     * @param claims receives the claim name and value.
     */
    public void contribute(final BiConsumer<String, Object> claims) {
        if (x509Properties.port() <= 0) {
            return;
        }
        final var context = AuthorizationServerContextHolder.getContext();
        final var issuer = context == null ? settings.getIssuer() : context.getIssuer();
        if (issuer == null) {
            return;
        }
        final var aliases = new LinkedHashMap<String, Object>();
        put(aliases, "token_endpoint", issuer, settings.getTokenEndpoint());
        put(aliases, "revocation_endpoint", issuer, settings.getTokenRevocationEndpoint());
        put(aliases, "introspection_endpoint", issuer, settings.getTokenIntrospectionEndpoint());
        put(aliases, "pushed_authorization_request_endpoint", issuer, settings.getPushedAuthorizationRequestEndpoint());
        put(aliases, "device_authorization_endpoint", issuer, settings.getDeviceAuthorizationEndpoint());
        claims.accept(CLAIM, Map.copyOf(aliases));
    }

    /**
     * Adds the alias of an endpoint.
     *
     * @param aliases  receives the alias.
     * @param name     metadata name of the endpoint.
     * @param issuer   the issuer, whose host and path prefix the alias keeps.
     * @param endpoint path of the endpoint.
     */
    private void put(final Map<String, Object> aliases, final String name, final String issuer, final String endpoint) {
        aliases.put(name, UriComponentsBuilder.fromUriString(issuer).scheme(HTTPS).port(x509Properties.port())
                .path(endpoint).build().toUriString());
    }
}
