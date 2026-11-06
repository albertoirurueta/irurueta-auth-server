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

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Applies the OpenID Connect step-up parameters of an authorization request to the authentication of the session. It
 * is installed first among the converters of {@code /oauth2/authorize} and never converts anything: it either lets
 * the request go on (returning {@code null}) or refuses it. The factors and their instants are read through the
 * {@link FactorTimeline}, so a remembered (trusted) device never counts here.
 *
 * <ul>
 *   <li>{@code max_age}: when the primary factor was presented more than that many whole seconds ago, a
 *       {@link ReauthenticationRequiredException} makes the user sign in again. A session whose factors are unknown
 *       (no counted factor of the registry) is left alone, because it could never satisfy the request and the user
 *       would loop through the login page.</li>
 *   <li>{@code acr_values}: when the request asks only for classes of {@link AuthenticationContextClass} that the
 *       session has not reached, a step-up {@link SecondFactorRequiredException} sends the user to the second-factor
 *       page, which then asks for a real second factor even on a trusted device. The multi-factor class also
 *       satisfies a request for the password class. Classes this server does not know are ignored, as the
 *       specification makes {@code acr_values} voluntary.</li>
 * </ul>
 */
@RequiredArgsConstructor
public class StepUpAuthorizationRequestConverter implements AuthenticationConverter {

    /** Name of the request parameter with the maximum age, in seconds, of the authentication. */
    public static final String MAX_AGE_PARAMETER = "max_age";

    /** Name of the request parameter with the space-separated authentication context classes asked for. */
    public static final String ACR_VALUES_PARAMETER = "acr_values";

    /** Reads the counted factors of the session and their instants. */
    private final FactorTimeline factorTimeline;

    /** Clock the age of the authentication is measured with. */
    private final Clock clock;

    // tag::mfa-step-up-converter[]
    /**
     * Checks the step-up parameters of a request.
     *
     * @param request the request.
     * @return always {@code null}: this converter only vetoes requests.
     * @throws ReauthenticationRequiredException if {@code max_age} is exceeded.
     * @throws SecondFactorRequiredException     if the requested {@code acr_values} are not reached.
     */
    @Override
    public Authentication convert(final HttpServletRequest request) {
        final var user = SecurityContextHolder.getContext().getAuthentication();
        if (!MfaAuthorizationManager.isUser(user)) {
            return null;
        }
        final var authTime = factorTimeline.authTime(user);
        if (authTime.isEmpty()) {
            return null;
        }
        if (maxAgeExceeded(request.getParameter(MAX_AGE_PARAMETER), authTime.get())) {
            throw new ReauthenticationRequiredException();
        }
        if (!acrReached(request.getParameter(ACR_VALUES_PARAMETER), factorTimeline.isMultiFactor(user))) {
            throw SecondFactorRequiredException.forStepUp();
        }
        return null;
    }
    // end::mfa-step-up-converter[]

    /**
     * Tells whether the authentication is older than the request tolerates.
     *
     * @param maxAge   the {@code max_age} parameter, may be {@code null}; a value that is not a non-negative integer
     *                 is ignored.
     * @param authTime the instant the primary factor was presented.
     * @return {@code true} when more than {@code maxAge} whole seconds have elapsed.
     */
    private boolean maxAgeExceeded(final String maxAge, final Instant authTime) {
        if (!StringUtils.hasText(maxAge)) {
            return false;
        }
        final long limit;
        try {
            limit = Long.parseLong(maxAge.trim());
        } catch (final NumberFormatException e) {
            return false;
        }
        return limit >= 0 && Duration.between(authTime, clock.instant()).getSeconds() > limit;
    }

    /**
     * Tells whether the session reached any of the requested classes.
     *
     * @param acrValues   the space-separated {@code acr_values} parameter, may be {@code null}.
     * @param multiFactor whether the session presented at least two distinct factors.
     * @return {@code true} when no known class is requested or one of them is reached.
     */
    private static boolean acrReached(final String acrValues, final boolean multiFactor) {
        if (!StringUtils.hasText(acrValues)) {
            return true;
        }
        final var known = Arrays.stream(acrValues.trim().split("\\s+"))
                .filter(acr -> AuthenticationContextClass.PASSWORD.equals(acr)
                        || AuthenticationContextClass.MULTI_FACTOR.equals(acr))
                .toList();
        return known.isEmpty() || multiFactor || known.contains(AuthenticationContextClass.PASSWORD);
    }
}
