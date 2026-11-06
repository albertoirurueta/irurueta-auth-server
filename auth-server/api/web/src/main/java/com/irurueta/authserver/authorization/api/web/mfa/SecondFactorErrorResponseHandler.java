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

package com.irurueta.authserver.authorization.api.web.mfa;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * Error handler of the authorization endpoint: a {@link SecondFactorRequiredException} goes to the entry point of the
 * second-factor page, a {@link ReauthenticationRequiredException} to the one that forces a new sign-in, and any other
 * error is answered as Spring Authorization Server's own handler does (a redirect to
 * the client's redirect URI carrying the error, or a 400 when there is none). Installing a handler replaces the
 * framework's, which is not reachable, so the default behaviour is reproduced here.
 */
@RequiredArgsConstructor
public class SecondFactorErrorResponseHandler implements AuthenticationFailureHandler {

    /** Strategy that redirects, honouring the context path. */
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /** Entry point that sends the user to the second-factor page. */
    private final AuthenticationEntryPoint secondFactorEntryPoint;

    /** Entry point that discards the stale authentication and sends the user to the login page. */
    private final AuthenticationEntryPoint reauthenticationEntryPoint;

    /**
     * Handles a failed authorization request.
     *
     * @param request   the request.
     * @param response  the response.
     * @param exception why the request failed.
     * @throws IOException      if the response cannot be written.
     * @throws ServletException if the entry point fails.
     */
    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
                                        final AuthenticationException exception) throws IOException, ServletException {
        if (exception instanceof SecondFactorRequiredException) {
            secondFactorEntryPoint.commence(request, response, exception);
            return;
        }
        if (exception instanceof ReauthenticationRequiredException) {
            reauthenticationEntryPoint.commence(request, response, exception);
            return;
        }
        final var error = exception instanceof OAuth2AuthenticationException oauth2 ? oauth2.getError() : null;
        final var redirectUri = redirectUriOf(exception);
        if (error == null || !StringUtils.hasText(redirectUri)) {
            response.sendError(HttpStatus.BAD_REQUEST.value(),
                    error == null ? exception.getMessage() : error.toString());
            return;
        }
        final var builder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
        if (StringUtils.hasText(error.getDescription())) {
            builder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION,
                    UriUtils.encode(error.getDescription(), StandardCharsets.UTF_8));
        }
        if (StringUtils.hasText(error.getUri())) {
            builder.queryParam(OAuth2ParameterNames.ERROR_URI,
                    UriUtils.encode(error.getUri(), StandardCharsets.UTF_8));
        }
        final var state = stateOf(exception);
        if (StringUtils.hasText(state)) {
            builder.queryParam(OAuth2ParameterNames.STATE, UriUtils.encode(state, StandardCharsets.UTF_8));
        }
        redirectStrategy.sendRedirect(request, response, builder.build(true).toUriString());
    }

    /**
     * Finds the redirect URI of the request that failed.
     *
     * @param exception the failure.
     * @return the redirect URI, or {@code null} when the failure does not carry one.
     */
    private static String redirectUriOf(final AuthenticationException exception) {
        final var token = requestOf(exception);
        return token == null ? null : token.getRedirectUri();
    }

    /**
     * Finds the state of the request that failed.
     *
     * @param exception the failure.
     * @return the state, or {@code null} when the failure does not carry one.
     */
    private static String stateOf(final AuthenticationException exception) {
        final var token = requestOf(exception);
        return token == null ? null : token.getState();
    }

    /**
     * Finds the authorization request that failed.
     *
     * @param exception the failure.
     * @return the request, or {@code null} when the failure does not carry one.
     */
    private static OAuth2AuthorizationCodeRequestAuthenticationToken requestOf(
            final AuthenticationException exception) {
        return exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException failure
                ? failure.getAuthorizationCodeRequestAuthentication() : null;
    }
}
