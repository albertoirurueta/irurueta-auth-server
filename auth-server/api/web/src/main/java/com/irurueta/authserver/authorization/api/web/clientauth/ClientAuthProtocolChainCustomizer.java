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

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.X509ClientCertificateAuthenticationProvider;

// tag::clientauth-chain[]
/**
 * Installs {@code private_key_jwt} with replay protection and the mutual-TLS client authentication in the protocol
 * chain: the framework's assertion provider decodes with {@link RegisteredJwksClientAssertionDecoderFactory}, and its
 * certificate provider verifies with {@link ClientCertificateVerifier}. The server metadata (the OpenID provider
 * configuration and the OAuth 2.0 authorization server metadata) also advertises {@code mtls_endpoint_aliases}.
 */
@RequiredArgsConstructor
public class ClientAuthProtocolChainCustomizer implements ProtocolChainCustomizer {

    /** Order of the customizer: after the multi-factor, step-up and device ones. */
    public static final int ORDER = 3;

    /** Creates the decoders of the client assertions. */
    private final RegisteredJwksClientAssertionDecoderFactory decoderFactory;

    /** Verifies the client certificates. */
    private final ClientCertificateVerifier certificateVerifier;

    /** Builds the {@code mtls_endpoint_aliases} claim. */
    private final MtlsEndpointAliases endpointAliases;

    /**
     * Customizes the client authentication and the metadata.
     *
     * @param server configurer of the authorization server.
     */
    @Override
    public void customize(final OAuth2AuthorizationServerConfigurer server) {
        server.clientAuthentication(client -> client.authenticationProviders(this::configure));
        server.authorizationServerMetadataEndpoint(metadata -> metadata.authorizationServerMetadataCustomizer(
                builder -> endpointAliases.contribute(builder::claim)));
        server.oidc(oidc -> oidc.providerConfigurationEndpoint(configuration ->
                configuration.providerConfigurationCustomizer(builder -> endpointAliases.contribute(builder::claim))));
    }

    /**
     * Sets the decoder factory and the certificate verifier on the framework's providers.
     *
     * @param providers the providers of the client authentication.
     */
    private void configure(final List<AuthenticationProvider> providers) {
        for (final var provider : providers) {
            if (provider instanceof JwtClientAssertionAuthenticationProvider assertions) {
                assertions.setJwtDecoderFactory(decoderFactory);
            } else if (provider instanceof X509ClientCertificateAuthenticationProvider certificates) {
                certificates.setCertificateVerifier(certificateVerifier);
            }
        }
    }
}
// end::clientauth-chain[]
