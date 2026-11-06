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

package com.irurueta.authserver.authorization.api.web.totp;

import static com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredEntryPoint.SECOND_FACTOR_PATH;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.api.web.mfa.TrustedDeviceCookieWriter;
import com.irurueta.authserver.authorization.application.mfa.CreateTrustedDeviceUseCase;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.StringUtils;

/**
 * Processes the post of the second-factor forms ({@code POST /login/second-factor/totp}): the TOTP form and the
 * recovery-code form. The code is verified by {@link TotpAuthenticationProvider}; on success the enriched
 * authentication is saved to the session, a device is remembered when the user asked for it and the browser resumes
 * the request that was interrupted. On failure it is sent back to the second-factor page with {@code ?error}. The
 * endpoint is owned by this filter, like {@code POST /login}, so it is not part of the pages contract.
 */
public class TotpAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    /** Path the second-factor forms post to. */
    public static final String TOTP_PATH = SECOND_FACTOR_PATH + "/totp";

    /** Name of the form field that holds the code. */
    public static final String CODE_PARAMETER = "code";

    /** Name of the form field present when the code is a recovery code. */
    public static final String RECOVERY_PARAMETER = "recovery";

    /** Name of the form field present when the user asks to remember the device. */
    public static final String REMEMBER_PARAMETER = "rememberDevice";

    /** Longest user agent description kept, the size of the column that stores it. */
    static final int MAX_USER_AGENT_LENGTH = 255;

    /** Use case that remembers the device. */
    private final CreateTrustedDeviceUseCase createTrustedDeviceUseCase;

    /** Resolves the identifier of the account of the signed-in user. */
    private final SecondFactorUserResolver userResolver;

    /** Writes the cookie of a remembered device. */
    private final TrustedDeviceCookieWriter cookieWriter;

    /**
     * Creates the filter.
     *
     * @param authenticationManager     manager that holds the {@link TotpAuthenticationProvider}.
     * @param createTrustedDeviceUseCase use case that remembers the device.
     * @param userResolver              resolves the identifier of the account of the signed-in user.
     * @param cookieWriter              writes the cookie of a remembered device.
     */
    public TotpAuthenticationFilter(final AuthenticationManager authenticationManager,
            final CreateTrustedDeviceUseCase createTrustedDeviceUseCase, final SecondFactorUserResolver userResolver,
            final TrustedDeviceCookieWriter cookieWriter) {
        super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, TOTP_PATH), authenticationManager);
        this.createTrustedDeviceUseCase = createTrustedDeviceUseCase;
        this.userResolver = userResolver;
        this.cookieWriter = cookieWriter;
        setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        setAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(SECOND_FACTOR_PATH + "?error"));
    }

    // tag::totp-filter[]
    /**
     * Builds the verification request from the form and the authentication the user already holds.
     *
     * @param request  the request.
     * @param response the response.
     * @return the authentication with the TOTP factor added.
     * @throws AuthenticationException if nobody is signed in or the code is not accepted.
     */
    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
            throws AuthenticationException {
        final var current = SecurityContextHolder.getContext().getAuthentication();
        if (current == null || !current.isAuthenticated() || current instanceof AnonymousAuthenticationToken) {
            throw new InsufficientAuthenticationException("The user has not signed in yet");
        }
        final var code = StringUtils.trimWhitespace(request.getParameter(CODE_PARAMETER));
        final var recovery = request.getParameter(RECOVERY_PARAMETER) != null;
        return getAuthenticationManager().authenticate(
                new TotpAuthenticationToken(current, code == null ? "" : code, recovery));
    }

    /**
     * Remembers the device when the user asked for it, then saves the authentication and resumes the request.
     *
     * @param request    the request.
     * @param response   the response.
     * @param chain      the rest of the chain.
     * @param authResult the verified authentication.
     * @throws IOException      if the redirect cannot be sent.
     * @throws ServletException if the success handler fails.
     */
    @Override
    protected void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain, final Authentication authResult) throws IOException, ServletException {
        if (request.getParameter(REMEMBER_PARAMETER) != null) {
            final var created = createTrustedDeviceUseCase.execute(userResolver.userIdOf(authResult.getName()),
                    authResult.getName(), userAgentSummary(request));
            cookieWriter.write(response, created);
        }
        super.successfulAuthentication(request, response, chain, authResult);
    }
    // end::totp-filter[]

    /**
     * Describes the browser of a request.
     *
     * @param request the request.
     * @return the {@code User-Agent} header, cut to the size that is stored; {@code null} when there is none.
     */
    private static String userAgentSummary(final HttpServletRequest request) {
        final var userAgent = request.getHeader(HttpHeaders.USER_AGENT);
        if (!StringUtils.hasText(userAgent)) {
            return null;
        }
        return userAgent.length() > MAX_USER_AGENT_LENGTH ? userAgent.substring(0, MAX_USER_AGENT_LENGTH) : userAgent;
    }
}
