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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

/**
 * The OAuth2 client of the service client: its registrations, the authorized client manager that caches the access
 * tokens and renews them shortly before they expire, and the documents client that sends them. Nothing here depends
 * on a profile: every setting has a default, and a mutual TLS or {@code private_key_jwt} setup only fails when its
 * key or bundle is missing at the moment it is needed.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({ResourceServerProperties.class, ServiceClientAuthProperties.class,
        ServiceClientKeyProperties.class})
public class OAuth2ClientConfiguration {

    /**
     * Registrations of the client credentials and token exchange grants.
     *
     * @param mapper     builds the registrations.
     * @param properties settings of the service client.
     * @return the repository.
     */
    @Bean
    ClientRegistrationRepository serviceClientRegistrations(final ServiceClientRegistrationMapper mapper,
            final ServiceClientAuthProperties properties) {
        return new InMemoryClientRegistrationRepository(
                List.of(mapper.clientCredentials(properties), mapper.tokenExchange(properties)));
    }

    /**
     * The cache of the authorized clients, so a token is reused while it is valid.
     *
     * @param registrations the registrations.
     * @return the service.
     */
    @Bean
    OAuth2AuthorizedClientService serviceClientAuthorizedClients(final ClientRegistrationRepository registrations) {
        return new InMemoryOAuth2AuthorizedClientService(registrations);
    }

    /**
     * The authorized client manager. It works without a servlet request, as there is none in the CLI. A cached token
     * is renewed once less than {@code service-client.auth.refresh-before} of its life is left.
     *
     * @param registrations   the registrations.
     * @param clients         the cache of the authorized clients.
     * @param tokenClients    the clients of the token endpoint.
     * @param principalMapper builds the principal of the service client.
     * @param properties      settings of the service client.
     * @return the manager.
     */
    @Bean
    OAuth2AuthorizedClientManager serviceClientAuthorizedClientManager(
            final ClientRegistrationRepository registrations, final OAuth2AuthorizedClientService clients,
            final TokenEndpointClients tokenClients, final PrincipalMapper principalMapper,
            final ServiceClientAuthProperties properties) {
        // tag::client-credentials-manager[]
        final var clientCredentials = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials(grant -> grant
                        .accessTokenResponseClient(tokenClients.clientCredentials())
                        .clockSkew(properties.refreshBefore()))
                .build();
        final var clientCredentialsManager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, clients);
        clientCredentialsManager.setAuthorizedClientProvider(clientCredentials);
        // end::client-credentials-manager[]

        // tag::token-exchange-client[]
        // The builder has no token exchange method, so its provider is added with provider(...). The subject token is
        // the principal object of the call (see PrincipalMapper.user) and the actor token is the client's own client
        // credentials token, which is how the exchanged token names the client as actor.
        final var exchange = new TokenExchangeOAuth2AuthorizedClientProvider();
        exchange.setAccessTokenResponseClient(tokenClients.tokenExchange());
        exchange.setClockSkew(properties.refreshBefore());
        exchange.setActorTokenResolver(context -> {
            final var actor = clientCredentialsManager.authorize(OAuth2AuthorizeRequest
                    .withClientRegistrationId(ServiceClientRegistrationMapper.CLIENT_CREDENTIALS_REGISTRATION_ID)
                    .principal(principalMapper.serviceClient(properties.clientId()))
                    .build());
            return actor == null ? null : actor.getAccessToken();
        });
        // end::token-exchange-client[]

        final var manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, clients);
        manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
                .provider(clientCredentials)
                .provider(exchange)
                .build());
        return manager;
    }

    /**
     * Generates the key pair that signs the DPoP proofs, for the life of the process. Present only when {@code
     * service-client.auth.dpop} is {@code true}.
     *
     * @return the proof creator.
     * @throws JOSEException if the key cannot be generated.
     */
    @Bean
    @ConditionalOnProperty(prefix = "service-client.auth", name = "dpop", havingValue = "true")
    DPoPProofs serviceClientDPoPProofs() throws JOSEException {
        final var key = new ECKeyGenerator(Curve.P_256).generate();
        return new DPoPProofs(new DefaultDPoPProofFactory(key, JWSAlgorithm.ES256));
    }

    /**
     * The documents client of the service client itself, whose requests carry the client credentials token.
     *
     * @param documentsApis   builds documents clients.
     * @param principalMapper builds the principal of the service client.
     * @param properties      settings of the service client.
     * @return the documents client.
     */
    @Bean
    DocumentsApi serviceClientDocumentsApi(final DocumentsApis documentsApis, final PrincipalMapper principalMapper,
            final ServiceClientAuthProperties properties) {
        return documentsApis.forPrincipal(ServiceClientRegistrationMapper.CLIENT_CREDENTIALS_REGISTRATION_ID,
                principalMapper.serviceClient(properties.clientId()));
    }
}
