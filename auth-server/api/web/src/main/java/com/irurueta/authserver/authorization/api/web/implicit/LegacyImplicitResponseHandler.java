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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriUtils;

// tag::implicit-response-handler[]
/**
 * Answers the authorization endpoint: for the two results of the legacy implicit flow it redirects with {@code 302} to
 * the registered redirect URI and carries the token, or the error, in its fragment (so it never reaches a server log
 * as a query would); any other result is the framework's authorization code response and goes to the delegate. The
 * response is never cached and the browser sends no referrer, so the fragment does not leak through the next request.
 */
@RequiredArgsConstructor
public class LegacyImplicitResponseHandler implements AuthenticationSuccessHandler {

    /** Value of {@code Cache-Control} of the response. */
    static final String NO_STORE = "no-store";

    /** Value of {@code Referrer-Policy} of the response. */
    static final String NO_REFERRER = "no-referrer";

    /** Name of the {@code Referrer-Policy} header. */
    private static final String REFERRER_POLICY = "Referrer-Policy";

    /** Token type reported to the client. */
    private static final String BEARER = "Bearer";

    /** Answers the results that are not the legacy flow's. */
    private final AuthenticationSuccessHandler delegate;

    /**
     * Answers a result.
     *
     * @param request        the request.
     * @param response       the response.
     * @param authentication the result of the authorization request.
     * @throws IOException      if the response cannot be written.
     * @throws ServletException if the delegate fails.
     */
    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof LegacyImplicitAccessTokenToken granted) {
            redirect(response, granted.getRedirectUri(), grantedFragment(granted));
        } else if (authentication instanceof LegacyImplicitErrorToken refused) {
            redirect(response, refused.getRedirectUri(), errorFragment(refused));
        } else {
            delegate.onAuthenticationSuccess(request, response, authentication);
        }
    }

    /**
     * Builds the fragment of a granted request.
     *
     * @param granted the result.
     * @return the encoded fragment.
     */
    private static String grantedFragment(final LegacyImplicitAccessTokenToken granted) {
        final var token = granted.getAccessToken();
        final var parameters = new ArrayList<String>();
        parameters.add(parameter(OAuth2ParameterNames.ACCESS_TOKEN, token.getTokenValue()));
        parameters.add(parameter(OAuth2ParameterNames.TOKEN_TYPE, BEARER));
        parameters.add(parameter(OAuth2ParameterNames.EXPIRES_IN, Long.toString(expiresIn(token))));
        parameters.add(parameter(OAuth2ParameterNames.SCOPE, String.join(" ", granted.getScopes())));
        addState(parameters, granted.getState());
        return String.join("&", parameters);
    }

    /**
     * Builds the fragment of a refusal.
     *
     * @param refused the result.
     * @return the encoded fragment.
     */
    private static String errorFragment(final LegacyImplicitErrorToken refused) {
        final var parameters = new ArrayList<String>();
        parameters.add(parameter(OAuth2ParameterNames.ERROR, refused.getError()));
        if (StringUtils.hasText(refused.getDescription())) {
            parameters.add(parameter(OAuth2ParameterNames.ERROR_DESCRIPTION, refused.getDescription()));
        }
        addState(parameters, refused.getState());
        return String.join("&", parameters);
    }

    /**
     * Adds the state, when the request had one.
     *
     * @param parameters the encoded parameters.
     * @param state      the state, may be {@code null}.
     */
    private static void addState(final ArrayList<String> parameters, final String state) {
        if (StringUtils.hasText(state)) {
            parameters.add(parameter(OAuth2ParameterNames.STATE, state));
        }
    }

    /**
     * Encodes one parameter.
     *
     * @param name  name of the parameter.
     * @param value value of the parameter.
     * @return {@code name=value}, with the value encoded.
     */
    private static String parameter(final String name, final String value) {
        return name + "=" + UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
    }

    /**
     * Computes the lifetime of a token in seconds.
     *
     * @param token the token.
     * @return the seconds between its issue and its expiry.
     */
    private static long expiresIn(final OAuth2AccessToken token) {
        return Duration.between(token.getIssuedAt(), token.getExpiresAt()).getSeconds();
    }

    /**
     * Sends the redirect, with the headers that keep the fragment private.
     *
     * @param response    the response.
     * @param redirectUri the registered redirect URI.
     * @param fragment    the encoded fragment.
     * @throws IOException if the response cannot be written.
     */
    private static void redirect(final HttpServletResponse response, final String redirectUri, final String fragment)
            throws IOException {
        response.setHeader(HttpHeaders.CACHE_CONTROL, NO_STORE);
        response.setHeader(REFERRER_POLICY, NO_REFERRER);
        response.sendRedirect(redirectUri + "#" + fragment);
    }
}
// end::implicit-response-handler[]
