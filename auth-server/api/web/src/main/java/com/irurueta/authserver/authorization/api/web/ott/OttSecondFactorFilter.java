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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorController;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.OneTimeTokenPageApi;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.StringUtils;

/**
 * Processes the post of the one-time code form of the second factor ({@code POST /login/second-factor/ott}), in the
 * way {@code TotpAuthenticationFilter} processes the TOTP forms. The code is verified by
 * {@link OttSecondFactorAuthenticationProvider} against the binding id the session holds; on success the session id is
 * changed (and the CSRF token renewed, with the session authentication strategy of the chain, as the form login does),
 * the enriched authentication is saved to the session and the browser resumes the request that was interrupted. On
 * failure it goes back to the page where the code is typed with {@code ?error}. Only a user who has already presented a
 * primary factor may post. The endpoint is owned by this filter, like {@code POST /login}, so it is not part of the
 * pages contract.
 */
public class OttSecondFactorFilter extends AbstractAuthenticationProcessingFilter {

    /** Path the code form of the second factor posts to. */
    public static final String SECOND_FACTOR_OTT_PATH = SecondFactorController.SECOND_FACTOR_PATH + "/ott";

    /** Name of the form field that holds the code. */
    public static final String CODE_PARAMETER = "code";

    /** Rules about the session a second factor is presented in. */
    private final PrimaryFactorSession primaryFactorSession;

    /**
     * Creates the filter. Until the chain customizer hands it the session authentication strategy of the chain, it
     * changes the session id on success with a {@link ChangeSessionIdAuthenticationStrategy}.
     *
     * @param authenticationManager manager that holds the {@link OttSecondFactorAuthenticationProvider}.
     * @param primaryFactorSession  rules about the session a second factor is presented in.
     */
    public OttSecondFactorFilter(final AuthenticationManager authenticationManager,
            final PrimaryFactorSession primaryFactorSession) {
        super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, SECOND_FACTOR_OTT_PATH),
                authenticationManager);
        this.primaryFactorSession = primaryFactorSession;
        setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
        setAuthenticationSuccessHandler(new OttAuthenticationSuccessHandler(
                new SavedRequestAwareAuthenticationSuccessHandler()));
        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(
                OneTimeTokenPageApi.PATH_OTT_CODE_PAGE + "?error"));
    }

    /**
     * Builds the verification request from the form, the authentication the user already holds and the binding id of
     * the session.
     *
     * @param request  the request.
     * @param response the response.
     * @return the authentication with the second factor of the channel added.
     * @throws AuthenticationException if nobody has presented a primary factor yet or the code is not accepted.
     */
    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
            throws AuthenticationException {
        final var current = SecurityContextHolder.getContext().getAuthentication();
        if (!primaryFactorSession.holdsPrimaryFactor(current)) {
            throw new InsufficientAuthenticationException("The user has not presented a primary factor yet");
        }
        final var code = StringUtils.trimWhitespace(request.getParameter(CODE_PARAMETER));
        final var bindingId = PendingOtt.of(request).map(PendingOtt::bindingId).orElse("");
        return getAuthenticationManager().authenticate(
                new OttSecondFactorToken(current, code == null ? "" : code, bindingId));
    }
}
