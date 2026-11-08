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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.x509.X509Properties;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/** Unit tests of {@link MtlsEndpointAliases}. */
class MtlsEndpointAliasesTest {

    /** Issuer of the server. */
    private static final String ISSUER = "https://auth.example.com";

    /** Port of the dedicated TLS connector. */
    private static final int TLS_PORT = 9443;

    /** Settings with the default endpoint paths. */
    private final AuthorizationServerSettings settings = AuthorizationServerSettings.builder().build();

    /** Clears the server context. */
    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
    }

    /** The aliases point at the TLS port of the request's issuer. */
    @Test
    void contribute_whenPortIsConfigured_addsTheAliasesOfTheContextIssuer() {
        final var context = mock(AuthorizationServerContext.class);
        when(context.getIssuer()).thenReturn(ISSUER);
        AuthorizationServerContextHolder.setContext(context);
        final var claims = new HashMap<String, Object>();

        aliases(TLS_PORT).contribute(claims::put);

        @SuppressWarnings("unchecked")
        final var aliases = (Map<String, Object>) claims.get(MtlsEndpointAliases.CLAIM);
        assertEquals("https://auth.example.com:9443/oauth2/token", aliases.get("token_endpoint"));
        assertEquals("https://auth.example.com:9443/oauth2/revoke", aliases.get("revocation_endpoint"));
        assertEquals("https://auth.example.com:9443/oauth2/introspect", aliases.get("introspection_endpoint"));
        assertEquals("https://auth.example.com:9443/oauth2/par",
                aliases.get("pushed_authorization_request_endpoint"));
        assertEquals("https://auth.example.com:9443/oauth2/device_authorization",
                aliases.get("device_authorization_endpoint"));
    }

    /** Without a request context the configured issuer is used. */
    @Test
    void contribute_whenThereIsNoContext_usesTheConfiguredIssuer() {
        final var claims = new HashMap<String, Object>();
        final var configured = AuthorizationServerSettings.builder().issuer(ISSUER).build();

        new MtlsEndpointAliases(properties(TLS_PORT), configured).contribute(claims::put);

        @SuppressWarnings("unchecked")
        final var aliases = (Map<String, Object>) claims.get(MtlsEndpointAliases.CLAIM);
        assertEquals("https://auth.example.com:9443/oauth2/token", aliases.get("token_endpoint"));
    }

    /** Nothing is added when the TLS port is not configured. */
    @Test
    void contribute_whenPortIsNotConfigured_addsNothing() {
        final var claims = new HashMap<String, Object>();

        aliases(0).contribute(claims::put);

        assertNull(claims.get(MtlsEndpointAliases.CLAIM));
    }

    /** Nothing is added when no issuer is known. */
    @Test
    void contribute_whenNoIssuerIsKnown_addsNothing() {
        final var claims = new HashMap<String, Object>();

        aliases(TLS_PORT).contribute(claims::put);

        assertNull(claims.get(MtlsEndpointAliases.CLAIM));
    }

    /**
     * Builds the subject with a TLS port.
     *
     * @param port the TLS port.
     * @return the aliases builder.
     */
    private MtlsEndpointAliases aliases(final int port) {
        return new MtlsEndpointAliases(properties(port), settings);
    }

    /**
     * Builds the X.509 settings with a TLS port.
     *
     * @param port the TLS port.
     * @return the settings.
     */
    private static X509Properties properties(final int port) {
        return new X509Properties(false, "", List.of(), port, X509Properties.AMR_SMART_CARD, "", "", "PKCS12");
    }
}
