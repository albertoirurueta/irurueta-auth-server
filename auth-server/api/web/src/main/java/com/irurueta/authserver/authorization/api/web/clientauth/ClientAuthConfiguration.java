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
import com.irurueta.authserver.authorization.api.web.x509.X509Properties;
import com.irurueta.authserver.authorization.application.clientauth.ClientAssertionProperties;
import com.irurueta.authserver.authorization.application.clientauth.RegisterClientAssertionUseCase;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.X509ClientCertificateAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * Wires the client authentication methods {@code private_key_jwt} (with replay protection) and mutual TLS into the
 * protocol chain. Nothing outside this feature is edited: the chain applies every {@link ProtocolChainCustomizer}
 * bean, in order.
 */
@Configuration(value = "clientAuthWebConfiguration", proxyBeanMethods = false)
@EnableConfigurationProperties({MtlsProperties.class, ClientAssertionProperties.class, X509Properties.class})
public class ClientAuthConfiguration {

    /**
     * Loads the trusted certificate authorities once.
     *
     * @param properties the configured PEM files.
     * @param reader     reads the files.
     * @return the trust anchors.
     */
    @Bean
    public MtlsTrustAnchors mtlsTrustAnchors(final MtlsProperties properties, final TrustAnchorsReader reader) {
        return reader.read(properties.trustedAuthorities());
    }

    /**
     * Declares the validator of the lifetime and replay of the assertions.
     *
     * @param registerClientAssertion records the use of an assertion.
     * @param properties              settings of the assertions.
     * @return the validator.
     */
    @Bean
    public ReplayRejectingJwtValidator replayRejectingJwtValidator(
            final RegisterClientAssertionUseCase registerClientAssertion, final ClientAssertionProperties properties) {
        return new ReplayRejectingJwtValidator(registerClientAssertion, properties);
    }

    // tag::clientauth-decoder-bean[]
    /**
     * Declares the factory of the assertion decoders.
     *
     * @param replayValidator the validator of the lifetime and replay.
     * @return the factory.
     */
    @Bean
    public RegisteredJwksClientAssertionDecoderFactory registeredJwksClientAssertionDecoderFactory(
            final ReplayRejectingJwtValidator replayValidator) {
        return new RegisteredJwksClientAssertionDecoderFactory(replayValidator);
    }
    // end::clientauth-decoder-bean[]

    /**
     * Declares the verifier of the client certificates.
     *
     * @param trustAnchors         the trusted authorities.
     * @param registeredClients    finds the clients.
     * @param authorizationService stores the authorizations.
     * @return the verifier.
     */
    @Bean
    public ClientCertificateVerifier clientCertificateVerifier(final MtlsTrustAnchors trustAnchors,
            final RegisteredClientRepository registeredClients, final OAuth2AuthorizationService authorizationService) {
        return new ClientCertificateVerifier(trustAnchors,
                new X509ClientCertificateAuthenticationProvider(registeredClients, authorizationService));
    }

    /**
     * Declares the builder of the {@code mtls_endpoint_aliases} claim.
     *
     * @param x509Properties settings of the TLS port.
     * @param settings       settings of the protocol endpoints.
     * @return the builder.
     */
    @Bean
    public MtlsEndpointAliases mtlsEndpointAliases(final X509Properties x509Properties,
            final AuthorizationServerSettings settings) {
        return new MtlsEndpointAliases(x509Properties, settings);
    }

    /**
     * Declares the customizer of the protocol chain, applied after the multi-factor, step-up and device ones.
     *
     * @param decoderFactory    creates the assertion decoders.
     * @param verifier          verifies the client certificates.
     * @param endpointAliases   builds the metadata claim.
     * @return the customizer.
     */
    @Bean
    @Order(ClientAuthProtocolChainCustomizer.ORDER)
    public ProtocolChainCustomizer clientAuthProtocolChainCustomizer(
            final RegisteredJwksClientAssertionDecoderFactory decoderFactory, final ClientCertificateVerifier verifier,
            final MtlsEndpointAliases endpointAliases) {
        return new ClientAuthProtocolChainCustomizer(decoderFactory, verifier, endpointAliases);
    }
}
