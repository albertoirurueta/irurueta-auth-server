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

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;

/**
 * Builds the OAuth2 client registrations of the service client from its settings: one for the client credentials
 * grant and one for the token exchange grant, which share the client's identity and authentication.
 */
@Component
public class ServiceClientRegistrationMapper {

    /** Registration id of the client credentials grant. */
    public static final String CLIENT_CREDENTIALS_REGISTRATION_ID = "service-client";

    /** Registration id of the token exchange grant. */
    public static final String TOKEN_EXCHANGE_REGISTRATION_ID = "service-client-token-exchange";

    /**
     * Builds the registration of the client credentials grant.
     *
     * @param properties settings of the service client.
     * @return the registration.
     */
    public ClientRegistration clientCredentials(final ServiceClientAuthProperties properties) {
        return registration(CLIENT_CREDENTIALS_REGISTRATION_ID, AuthorizationGrantType.CLIENT_CREDENTIALS, properties);
    }

    /**
     * Builds the registration of the token exchange grant.
     *
     * @param properties settings of the service client.
     * @return the registration.
     */
    public ClientRegistration tokenExchange(final ServiceClientAuthProperties properties) {
        return registration(TOKEN_EXCHANGE_REGISTRATION_ID, AuthorizationGrantType.TOKEN_EXCHANGE, properties);
    }

    /**
     * Builds a registration.
     *
     * @param registrationId id of the registration.
     * @param grantType      grant the registration is for.
     * @param properties     settings of the service client.
     * @return the registration.
     */
    private static ClientRegistration registration(final String registrationId,
            final AuthorizationGrantType grantType, final ServiceClientAuthProperties properties) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId(properties.clientId())
                .clientSecret(properties.clientSecret())
                .clientAuthenticationMethod(properties.method().getClientAuthenticationMethod())
                .authorizationGrantType(grantType)
                .tokenUri(properties.tokenUri().toString())
                .scope(properties.scopes())
                .build();
    }
}
