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

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

// tag::device-client-authentication[]
/**
 * Reads the identifier of a public client of the device flow, the only kind of client authentication that flow has
 * for a device that cannot keep a secret: the {@code client_id} of the request to the device authorization endpoint
 * and of the polling request to the token endpoint with the device code grant. Spring Authorization Server's public
 * client authentication needs a PKCE code verifier, which the device flow does not have. A request that carries any
 * other credential (an {@code Authorization} header, a client secret or a client assertion) is left to the
 * converters of those credentials.
 */
public class DeviceClientAuthenticationConverter implements AuthenticationConverter {

    /** Names of the parameters that carry a credential of a confidential client. */
    private static final List<String> CREDENTIAL_PARAMETERS = List.of(
            OAuth2ParameterNames.CLIENT_SECRET, OAuth2ParameterNames.CLIENT_ASSERTION,
            OAuth2ParameterNames.CLIENT_ASSERTION_TYPE);

    /** Matches the request for the codes, which names the client. */
    private final RequestMatcher deviceAuthorizationRequest;

    /**
     * Creates the converter.
     *
     * @param deviceAuthorizationEndpoint path of the device authorization endpoint.
     */
    public DeviceClientAuthenticationConverter(final String deviceAuthorizationEndpoint) {
        deviceAuthorizationRequest = PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.POST, deviceAuthorizationEndpoint);
    }

    /**
     * Reads the client of a request.
     *
     * @param request the request.
     * @return the request to authenticate the public client, or {@code null} when the request is not one of the device
     *         flow's or carries a credential.
     * @throws OAuth2AuthenticationException {@code invalid_request} if the client is named more than once or not at
     *                                       all.
     */
    @Override
    public Authentication convert(final HttpServletRequest request) {
        if (!isDeviceRequest(request) || carriesCredential(request)) {
            return null;
        }
        final var clientIds = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
        if (clientIds == null || clientIds.length != 1 || !StringUtils.hasText(clientIds[0])) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return new DeviceClientAuthenticationToken(clientIds[0]);
    }

    /**
     * Tells whether the request is one of the device flow's: the request for the codes, or the poll with the device
     * code grant.
     *
     * @param request the request.
     * @return {@code true} for a device flow request that names a client.
     */
    private boolean isDeviceRequest(final HttpServletRequest request) {
        if (request.getParameter(OAuth2ParameterNames.CLIENT_ID) == null) {
            return false;
        }
        return deviceAuthorizationRequest.matches(request) || isDeviceCodePoll(request);
    }

    /**
     * Tells whether the request is a poll of the token endpoint with the device code grant.
     *
     * @param request the request.
     * @return {@code true} when it is.
     */
    private static boolean isDeviceCodePoll(final HttpServletRequest request) {
        return AuthorizationGrantType.DEVICE_CODE.getValue().equals(request.getParameter(
                OAuth2ParameterNames.GRANT_TYPE)) && request.getParameter(OAuth2ParameterNames.DEVICE_CODE) != null;
    }

    /**
     * Tells whether the request carries the credential of a confidential client.
     *
     * @param request the request.
     * @return {@code true} when it does.
     */
    private static boolean carriesCredential(final HttpServletRequest request) {
        return request.getHeader(HttpHeaders.AUTHORIZATION) != null
                || CREDENTIAL_PARAMETERS.stream().anyMatch(name -> request.getParameter(name) != null);
    }
}
// end::device-client-authentication[]
