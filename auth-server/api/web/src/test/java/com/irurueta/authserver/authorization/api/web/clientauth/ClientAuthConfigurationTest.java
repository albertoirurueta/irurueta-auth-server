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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import com.irurueta.authserver.authorization.api.web.x509.X509Properties;
import com.irurueta.authserver.authorization.application.clientauth.ClientAssertionProperties;
import com.irurueta.authserver.authorization.application.clientauth.RegisterClientAssertionUseCase;
import java.time.Clock;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/** Unit tests of {@link ClientAuthConfiguration}. */
class ClientAuthConfigurationTest {

    /** Configuration under test. */
    private final ClientAuthConfiguration configuration = new ClientAuthConfiguration();

    /** The trust anchors are the ones the reader returns for the configured paths. */
    @Test
    void mtlsTrustAnchors_whenPathsAreConfigured_returnsWhatTheReaderLoaded() {
        final var reader = mock(TrustAnchorsReader.class);
        final var loaded = new MtlsTrustAnchors(Set.of());
        final var paths = List.of("/etc/ca.pem");
        when(reader.read(paths)).thenReturn(loaded);

        assertSame(loaded, configuration.mtlsTrustAnchors(new MtlsProperties(paths), reader));

        verify(reader).read(paths);
    }

    /** The beans are created. */
    @Test
    void beans_whenCreated_areNotNull() {
        final var properties = new ClientAssertionProperties(null, null);
        final var validator = configuration.replayRejectingJwtValidator(
                mock(RegisterClientAssertionUseCase.class), properties, Clock.systemUTC());
        final var decoderFactory = configuration.registeredJwksClientAssertionDecoderFactory(validator);
        final var verifier = configuration.clientCertificateVerifier(new MtlsTrustAnchors(Set.of()),
                mock(RegisteredClientRepository.class), mock(OAuth2AuthorizationService.class));
        final var aliases = configuration.mtlsEndpointAliases(
                new X509Properties(false, "", List.of(), 0, "sc", "", "", "PKCS12"),
                AuthorizationServerSettings.builder().build());

        assertNotNull(validator);
        assertNotNull(decoderFactory);
        assertNotNull(verifier);
        assertNotNull(aliases);
        assertTrue(configuration.clientAuthProtocolChainCustomizer(decoderFactory, verifier, aliases)
                instanceof ClientAuthProtocolChainCustomizer);
    }

    /** The customizer bean has the documented order. */
    @Test
    void clientAuthProtocolChainCustomizer_whenDeclared_hasOrderThree() throws NoSuchMethodException {
        final var method = ClientAuthConfiguration.class.getMethod("clientAuthProtocolChainCustomizer",
                RegisteredJwksClientAssertionDecoderFactory.class, ClientCertificateVerifier.class,
                MtlsEndpointAliases.class);

        assertEquals(ClientAuthProtocolChainCustomizer.ORDER, method.getAnnotation(Order.class).value());
        assertEquals(ProtocolChainCustomizer.class, method.getReturnType());
    }

    /** The assertion, mTLS and X.509 settings (the latter for the mTLS endpoint aliases) are bound as beans by this
     * configuration. */
    @Test
    void configuration_whenInspected_enablesTheAssertionAndMtlsProperties() {
        final var enabled = AnnotatedElementUtils.findMergedAnnotation(ClientAuthConfiguration.class,
                EnableConfigurationProperties.class);

        assertEquals(Set.of(MtlsProperties.class, ClientAssertionProperties.class, X509Properties.class),
                Set.of(enabled.value()));
    }
}
