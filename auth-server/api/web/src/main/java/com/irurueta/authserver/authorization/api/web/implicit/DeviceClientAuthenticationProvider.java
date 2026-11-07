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
package com.irurueta.authserver.authorization.api.web.implicit;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Authenticates a public client of the device flow by its identifier: the client must be registered and must have
 * registered the {@code none} authentication method, which is what makes it public. It accepts only the requests
 * {@link DeviceClientAuthenticationConverter} built (a {@link DeviceClientAuthenticationToken}), so it can never stand
 * in for the PKCE verification of another request of a public client.
 */
@RequiredArgsConstructor
public class DeviceClientAuthenticationProvider implements AuthenticationProvider {

    /** Reference to the standard that describes the failure. */
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    /** Finds the registered clients. */
    private final RegisteredClientRepository registeredClientRepository;

    /**
     * Authenticates the client.
     *
     * @param authentication the request of a public client of the device flow.
     * @return the authenticated client.
     * @throws AuthenticationException {@code invalid_client} if the client is unknown or is not a public one.
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final var request = (DeviceClientAuthenticationToken) authentication;
        final var registeredClient = registeredClientRepository.findByClientId(request.clientId());
        if (registeredClient == null) {
            throw invalidClient("client_id");
        }
        if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            throw invalidClient("authentication_method");
        }
        return new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.NONE, null);
    }

    /**
     * Tells which requests this provider authenticates.
     *
     * @param authentication the type of the request.
     * @return {@code true} for a {@link DeviceClientAuthenticationToken}.
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return DeviceClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Builds the failure.
     *
     * @param parameterName what failed.
     * @return the exception.
     */
    private static OAuth2AuthenticationException invalidClient(final String parameterName) {
        return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                "Client authentication failed: " + parameterName, ERROR_URI));
    }
}
