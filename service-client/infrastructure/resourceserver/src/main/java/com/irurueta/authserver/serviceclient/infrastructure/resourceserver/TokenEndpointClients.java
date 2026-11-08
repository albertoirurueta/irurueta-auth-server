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

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.AbstractRestClientOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * Builds the clients of the token endpoint for the two grants, set up for the configured authentication method: the
 * default for {@code client_secret_basic}; the signed assertion for {@code private_key_jwt}; a REST client over the
 * SSL bundle (so the client certificate is presented) for the mutual TLS methods; plus a DPoP proof header when DPoP
 * is enabled.
 */
@Component
@RequiredArgsConstructor
public class TokenEndpointClients {

    /** Settings of the service client at the authorization server. */
    private final ServiceClientAuthProperties properties;

    /** Signing key of the assertion. */
    private final PrivateKeyJwkResolver jwkResolver;

    /** Request factory that presents the client certificate. */
    private final SslRequestFactories requestFactories;

    /** Creates the DPoP proofs; absent unless DPoP is enabled. */
    private final ObjectProvider<DPoPProofs> dpopProofs;

    /**
     * Builds the client of the client credentials grant.
     *
     * @return the client.
     */
    public RestClientClientCredentialsTokenResponseClient clientCredentials() {
        final var client = new RestClientClientCredentialsTokenResponseClient();
        customize(client);
        return client;
    }

    /**
     * Builds the client of the token exchange grant.
     *
     * @return the client.
     */
    public RestClientTokenExchangeTokenResponseClient tokenExchange() {
        final var client = new RestClientTokenExchangeTokenResponseClient();
        customize(client);
        return client;
    }

    /**
     * Sets a token response client up for the configured authentication method.
     *
     * @param client the client.
     * @param <T>    grant request of the client.
     */
    private <T extends AbstractOAuth2AuthorizationGrantRequest> void customize(
            final AbstractRestClientOAuth2AccessTokenResponseClient<T> client) {
        requestFactories.create().ifPresent(factory -> client.setRestClient(tokenRestClient(factory)));
        if (properties.method() == AuthMethod.PRIVATE_KEY_JWT) {
            client.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<T>(jwkResolver));
        }
        if (properties.method().isMutualTls()) {
            // The client is identified by its certificate: nothing to add to the request but, as it is, the client
            // refuses any method other than basic, post and none. Adding any parameters converter (this one adds
            // nothing) lifts that check; the default converter still sends client_id.
            client.addParametersConverter(request -> new LinkedMultiValueMap<>());
        }
        final var proofs = dpopProofs.getIfAvailable();
        if (proofs != null) {
            client.addHeadersConverter(request -> {
                final var headers = new HttpHeaders();
                headers.set(DPoPClientHttpRequestInterceptor.DPOP_HEADER,
                        proofs.proof("POST", properties.tokenUri()));
                return headers;
            });
        }
    }

    /**
     * Builds the REST client of the token endpoint over a request factory, with the message converters and the error
     * handler of Spring Security's default one.
     *
     * @param factory the request factory.
     * @return the REST client.
     */
    private static RestClient tokenRestClient(final ClientHttpRequestFactory factory) {
        return RestClient.builder()
                .requestFactory(factory)
                .configureMessageConverters(converters -> {
                    converters.addCustomConverter(new FormHttpMessageConverter());
                    converters.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter());
                })
                .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
                .build();
    }
}
