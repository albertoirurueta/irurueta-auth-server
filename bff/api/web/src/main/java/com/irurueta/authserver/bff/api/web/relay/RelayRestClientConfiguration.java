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

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.client.RestClient;

/**
 * Builds the {@link RestClient} that talks to the resource server on behalf of the signed-in user.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(RelayProperties.class)
public class RelayRestClientConfiguration {

    /** Registration id of the OAuth2 client whose access token is relayed. */
    public static final String REGISTRATION_ID = "bff";

    // tag::bff-relay[]
    /**
     * Builds the relay client. Its interceptor asks the authorized client manager for the access token of the user of
     * the current request (renewing it with the refresh token when it expired) and sets it as the bearer token of the
     * outgoing request; a call whose session has no token is never sent. When the token cannot be obtained or renewed
     * it throws an {@link org.springframework.security.oauth2.core.OAuth2AuthorizationException}, which
     * {@link ApiRelayController} answers with a 401 so the SPA signs in again.
     *
     * @param builder the builder of REST clients, the one test slices bind a mock server to.
     * @param manager the manager of the authorized clients of the session.
     * @return the REST client of the relay.
     */
    @Bean
    RestClient relayRestClient(final RestClient.Builder builder, final OAuth2AuthorizedClientManager manager) {
        final var interceptor = new OAuth2ClientHttpRequestInterceptor(manager);
        interceptor.setClientRegistrationIdResolver(request -> REGISTRATION_ID);
        // The OAuth2 interceptor lets the call through unauthenticated when the session has no authorized client;
        // the relay must never do that, so the call stops here and the SPA gets a 401.
        return builder.requestInterceptor(interceptor).requestInterceptor((request, body, execution) -> {
            if (!request.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)) {
                throw new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,
                        "The session has no access token", null), REGISTRATION_ID);
            }
            return execution.execute(request, body);
        }).build();
    }
    // end::bff-relay[]
}
