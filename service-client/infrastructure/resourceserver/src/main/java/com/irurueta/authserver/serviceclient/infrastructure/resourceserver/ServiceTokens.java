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

import com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.stereotype.Component;

/**
 * Gives the access token the service client uses, for the CLI that is asked to print it. It goes through the same
 * authorized client manager as the calls, so the token is the cached one while it is valid and no extra request is
 * made.
 */
@Component
@RequiredArgsConstructor
public class ServiceTokens {

    /** Obtains and renews the access tokens. */
    private final OAuth2AuthorizedClientManager manager;

    /** Builds the principals the tokens are cached under. */
    private final PrincipalMapper principalMapper;

    /** Settings of the service client. */
    private final ServiceClientAuthProperties properties;

    /**
     * Gives the access token of the client credentials grant.
     *
     * @return the token value.
     * @throws DocumentAccessException if the token cannot be obtained.
     */
    public String clientCredentialsToken() {
        return token(ServiceClientRegistrationMapper.CLIENT_CREDENTIALS_REGISTRATION_ID,
                principalMapper.serviceClient(properties.clientId()));
    }

    /**
     * Gives the access token the authorization server issues for the client acting on behalf of a user.
     *
     * @param subjectToken access token of the user.
     * @return the exchanged token value.
     * @throws DocumentAccessException if the exchange fails.
     */
    public String exchangedToken(final String subjectToken) {
        return token(ServiceClientRegistrationMapper.TOKEN_EXCHANGE_REGISTRATION_ID,
                principalMapper.user(subjectToken));
    }

    /**
     * Obtains a token.
     *
     * @param registrationId registration of the OAuth2 client.
     * @param principal      principal the token is cached under.
     * @return the token value.
     */
    private String token(final String registrationId, final Authentication principal) {
        try {
            final var authorizedClient = manager.authorize(
                    OAuth2AuthorizeRequest.withClientRegistrationId(registrationId).principal(principal).build());
            if (authorizedClient == null) {
                throw new DocumentAccessException("No access token was issued", null);
            }
            return authorizedClient.getAccessToken().getTokenValue();
        } catch (final OAuth2AuthorizationException e) {
            throw new DocumentAccessException("The access token could not be obtained", e);
        }
    }
}
