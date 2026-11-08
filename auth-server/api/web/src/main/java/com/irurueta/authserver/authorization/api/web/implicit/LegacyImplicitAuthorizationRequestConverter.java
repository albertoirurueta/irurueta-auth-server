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
import java.util.Arrays;
import java.util.LinkedHashSet;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

// tag::implicit-converter[]
/**
 * Reads an authorization request with {@code response_type=token}. The framework refuses that response type; this
 * converter, installed first, takes it over for the one client of the legacy flow and refuses it, with the same
 * {@code unsupported_response_type} and no redirect, for any other client.
 */
public class LegacyImplicitAuthorizationRequestConverter implements AuthenticationConverter {

    /** Response type of the implicit flow. */
    public static final String RESPONSE_TYPE_TOKEN = "token";

    /** Identifier of the only client that may use the flow. */
    private final String clientId;

    /** Matches a {@code GET} of the authorization endpoint. */
    private final RequestMatcher authorizationRequest;

    /**
     * Creates the converter.
     *
     * @param clientId              identifier of the only client that may use the flow.
     * @param authorizationEndpoint path of the authorization endpoint.
     */
    public LegacyImplicitAuthorizationRequestConverter(final String clientId, final String authorizationEndpoint) {
        this.clientId = clientId;
        authorizationRequest = PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.GET, authorizationEndpoint);
    }

    /**
     * Reads the request.
     *
     * @param request the request.
     * @return the request of the legacy flow, or {@code null} when the request is not a {@code GET} of the
     *         authorization endpoint with {@code response_type=token}.
     * @throws OAuth2AuthorizationCodeRequestAuthenticationException {@code unsupported_response_type} (no redirect)
     *                                                               when the client is not the one of the legacy
     *                                                               flow, {@code invalid_request} (no redirect) when
     *                                                               a parameter is repeated.
     */
    @Override
    public Authentication convert(final HttpServletRequest request) {
        if (!authorizationRequest.matches(request)
                || !RESPONSE_TYPE_TOKEN.equals(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))) {
            return null;
        }
        final var requestedClient = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!clientId.equals(requestedClient)) {
            throw refused(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE);
        }
        if (isRepeated(request, OAuth2ParameterNames.CLIENT_ID) || isRepeated(request, OAuth2ParameterNames.SCOPE)
                || isRepeated(request, OAuth2ParameterNames.REDIRECT_URI)
                || isRepeated(request, OAuth2ParameterNames.STATE)) {
            throw refused(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        final var scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        final var scopes = StringUtils.hasText(scope)
                ? new LinkedHashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope.trim(), " ")))
                : new LinkedHashSet<String>();
        scopes.remove("");
        return new LegacyImplicitAuthorizationRequestToken(requestedClient,
                request.getParameter(OAuth2ParameterNames.REDIRECT_URI), scopes,
                request.getParameter(OAuth2ParameterNames.STATE), currentUser());
    }

    /**
     * Tells whether a parameter is sent more than once.
     *
     * @param request the request.
     * @param name    name of the parameter.
     * @return {@code true} when it has more than one value.
     */
    private static boolean isRepeated(final HttpServletRequest request, final String name) {
        final var values = request.getParameterValues(name);
        return values != null && values.length > 1;
    }

    /**
     * Reads the user of the request from the security context, an anonymous one when there is none.
     *
     * @return the user.
     */
    private static Authentication currentUser() {
        final var current = SecurityContextHolder.getContext().getAuthentication();
        return current != null ? current : new AnonymousAuthenticationToken("anonymous", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

    /**
     * Builds the refusal, which carries no authentication and so is answered with {@code 400}.
     *
     * @param code error code.
     * @return the exception.
     */
    private static OAuth2AuthorizationCodeRequestAuthenticationException refused(final String code) {
        return new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(code), null);
    }
}
// end::implicit-converter[]
