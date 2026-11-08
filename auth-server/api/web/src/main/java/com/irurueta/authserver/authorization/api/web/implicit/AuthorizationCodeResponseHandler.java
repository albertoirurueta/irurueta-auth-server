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
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * The framework's own answer to a granted authorization code request, repeated because installing a response handler
 * replaces it and the framework does not expose it: a redirect to the redirect URI with {@code code} and, when the
 * request had one, {@code state} in the query.
 */
public class AuthorizationCodeResponseHandler implements AuthenticationSuccessHandler {

    /**
     * Redirects the user agent with the authorization code.
     *
     * @param request        the request.
     * @param response       the response.
     * @param authentication the result, an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
     * @throws IOException if the response cannot be written.
     */
    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) throws IOException {
        final var result = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        final var redirectUri = result.getRedirectUri();
        Assert.notNull(redirectUri, "redirectUri cannot be null");
        final var code = result.getAuthorizationCode();
        Assert.notNull(code, "authorizationCode cannot be null");
        final var builder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.CODE, code.getTokenValue());
        if (StringUtils.hasText(result.getState())) {
            builder.queryParam(OAuth2ParameterNames.STATE, UriUtils.encode(result.getState(), StandardCharsets.UTF_8));
        }
        response.sendRedirect(builder.build(true).toUriString());
    }
}
