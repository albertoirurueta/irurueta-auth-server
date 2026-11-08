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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2ClientAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerMetadataEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcProviderConfigurationEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.X509ClientCertificateAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;

/** Unit tests of {@link ClientAuthProtocolChainCustomizer}. */
@ExtendWith(MockitoExtension.class)
class ClientAuthProtocolChainCustomizerTest {

    /** Order the customizer must have. */
    private static final int EXPECTED_ORDER = 3;

    /** Creates the assertion decoders. */
    @Mock
    private RegisteredJwksClientAssertionDecoderFactory decoderFactory;

    /** Verifies the certificates. */
    @Mock
    private ClientCertificateVerifier certificateVerifier;

    /** Builds the metadata claim. */
    @Mock
    private MtlsEndpointAliases endpointAliases;

    /** The order follows the device customizer. */
    @Test
    void order_whenRead_isAfterTheDeviceCustomizer() {
        assertEquals(EXPECTED_ORDER, ClientAuthProtocolChainCustomizer.ORDER);
    }

    /** The framework's providers receive the decoder factory and the verifier, and the others are left alone. */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenProvidersAreListed_configuresTheAssertionAndCertificateOnes() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class);
        final var clientConfigurer = mock(OAuth2ClientAuthenticationConfigurer.class);
        when(server.clientAuthentication(any())).thenAnswer(invocation -> {
            invocation.<Customizer<OAuth2ClientAuthenticationConfigurer>>getArgument(0).customize(clientConfigurer);
            return server;
        });
        final var assertions = mock(JwtClientAssertionAuthenticationProvider.class);
        final var certificates = mock(X509ClientCertificateAuthenticationProvider.class);
        final var other = mock(AuthenticationProvider.class);
        final var captor = ArgumentCaptor.<Consumer<List<AuthenticationProvider>>>captor();

        customizer(server);
        verify(clientConfigurer).authenticationProviders(captor.capture());
        captor.getValue().accept(new ArrayList<>(List.of(assertions, certificates, other)));

        verify(assertions).setJwtDecoderFactory(decoderFactory);
        verify(certificates).setCertificateVerifier(certificateVerifier);
        verify(other, never()).authenticate(any());
    }

    /** Both metadata documents get the aliases claim. */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenMetadataIsBuilt_contributesTheAliasesToBothDocuments() {
        final var server = mock(OAuth2AuthorizationServerConfigurer.class);
        final var metadataConfigurer = mock(OAuth2AuthorizationServerMetadataEndpointConfigurer.class);
        final var oidcConfigurer = mock(OidcConfigurer.class);
        final var providerConfigurer = mock(OidcProviderConfigurationEndpointConfigurer.class);
        when(server.authorizationServerMetadataEndpoint(any())).thenAnswer(invocation -> {
            invocation.<Customizer<OAuth2AuthorizationServerMetadataEndpointConfigurer>>getArgument(0)
                    .customize(metadataConfigurer);
            return server;
        });
        when(server.oidc(any())).thenAnswer(invocation -> {
            invocation.<Customizer<OidcConfigurer>>getArgument(0).customize(oidcConfigurer);
            return server;
        });
        when(oidcConfigurer.providerConfigurationEndpoint(any())).thenAnswer(invocation -> {
            invocation.<Customizer<OidcProviderConfigurationEndpointConfigurer>>getArgument(0)
                    .customize(providerConfigurer);
            return oidcConfigurer;
        });
        final var metadataCaptor = ArgumentCaptor.<Consumer<OAuth2AuthorizationServerMetadata.Builder>>captor();
        final var providerCaptor = ArgumentCaptor.<Consumer<OidcProviderConfiguration.Builder>>captor();

        customizer(server);
        verify(metadataConfigurer).authorizationServerMetadataCustomizer(metadataCaptor.capture());
        verify(providerConfigurer).providerConfigurationCustomizer(providerCaptor.capture());
        metadataCaptor.getValue().accept(
                OAuth2AuthorizationServerMetadata.builder());
        providerCaptor.getValue().accept(
                OidcProviderConfiguration.builder());

        verify(endpointAliases, times(2)).contribute(any());
    }

    /**
     * Runs the customizer on a server configurer.
     *
     * @param server the configurer.
     */
    private void customizer(final OAuth2AuthorizationServerConfigurer server) {
        new ClientAuthProtocolChainCustomizer(decoderFactory, certificateVerifier, endpointAliases).customize(server);
    }
}
