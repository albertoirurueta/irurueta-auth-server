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

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Unit tests of {@link StepUpAuthorizationRequestConverter}.
 */
class StepUpAuthorizationRequestConverterTest {

    /** Authority of the password factor. */
    private static final String PASSWORD_AUTHORITY = "FACTOR_PASSWORD";

    /** Authority of the TOTP factor. */
    private static final String TOTP_AUTHORITY = "FACTOR_TOTP";

    /** Current instant of the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");

    /** Seconds the password was presented before {@link #NOW}. */
    private static final long AGE_SECONDS = 600;

    /** A {@code max_age} lower than the age. */
    private static final String SMALL_MAX_AGE = "60";

    /** A {@code max_age} greater than the age. */
    private static final String LARGE_MAX_AGE = "3600";

    /** Converter under test, over a fixed clock. */
    private final StepUpAuthorizationRequestConverter converter = new StepUpAuthorizationRequestConverter(
            new AuthenticationFactorRegistry(List.of(
                    new AuthenticationFactor("password", "pwd", PASSWORD_AUTHORITY, FactorStrength.PRIMARY),
                    new AuthenticationFactor("totp", "otp", TOTP_AUTHORITY, FactorStrength.SECOND))),
            Clock.fixed(NOW, ZoneOffset.UTC));

    /**
     * Leaves the thread's security context clean.
     */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that a request without step-up parameters goes on.
     */
    @Test
    void convert_whenNoStepUpParameters_returnsNull() {
        signIn(passwordOnly());

        assertNull(converter.convert(new MockHttpServletRequest()));
    }

    /**
     * Verifies that nobody signed in is left to the framework.
     */
    @Test
    void convert_whenNobodyIsSignedIn_returnsNull() {
        assertNull(converter.convert(request(SMALL_MAX_AGE, null)));
    }

    /**
     * Verifies that an anonymous user is left to the framework.
     */
    @Test
    void convert_whenUserIsAnonymous_returnsNull() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anon",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        assertNull(converter.convert(request(SMALL_MAX_AGE, null)));
    }

    /**
     * Verifies that a session with no known factor cannot be judged and is left alone.
     */
    @Test
    void convert_whenNoKnownFactor_returnsNull() {
        signIn(UsernamePasswordAuthenticationToken.authenticated("alice", null,
                AuthorityUtils.createAuthorityList("ROLE_USER")));

        assertNull(converter.convert(request(SMALL_MAX_AGE, AuthenticationContextClass.MULTI_FACTOR)));
    }

    /**
     * Verifies that an authentication older than {@code max_age} forces a new sign-in.
     */
    @Test
    void convert_whenMaxAgeIsExceeded_throwsReauthenticationRequiredException() {
        signIn(passwordOnly());
        final var request = request(SMALL_MAX_AGE, null);

        assertThrows(ReauthenticationRequiredException.class, () -> converter.convert(request));
    }

    /**
     * Verifies that {@code max_age=0} forces a new sign-in of any authentication older than a second.
     */
    @Test
    void convert_whenMaxAgeIsZero_throwsReauthenticationRequiredException() {
        signIn(passwordOnly());
        final var request = request("0", null);

        assertThrows(ReauthenticationRequiredException.class, () -> converter.convert(request));
    }

    /**
     * Verifies that a recent enough authentication goes on.
     */
    @Test
    void convert_whenMaxAgeIsNotExceeded_returnsNull() {
        signIn(passwordOnly());

        assertNull(converter.convert(request(LARGE_MAX_AGE, null)));
    }

    /**
     * Verifies that an invalid or negative {@code max_age} is ignored.
     */
    @Test
    void convert_whenMaxAgeIsInvalid_returnsNull() {
        signIn(passwordOnly());

        assertNull(converter.convert(request("abc", null)));
        assertNull(converter.convert(request("-5", null)));
        assertNull(converter.convert(request(" ", null)));
    }

    /**
     * Verifies that the latest factor decides the age of the authentication.
     */
    @Test
    void convert_whenLastFactorIsRecent_doesNotExceedMaxAge() {
        signIn(UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of(
                FactorGrantedAuthority.withAuthority(PASSWORD_AUTHORITY).issuedAt(NOW.minusSeconds(AGE_SECONDS))
                        .build(),
                FactorGrantedAuthority.withAuthority(TOTP_AUTHORITY).issuedAt(NOW.minus(Duration.ofSeconds(1)))
                        .build())));

        assertNull(converter.convert(request(SMALL_MAX_AGE, null)));
    }

    /**
     * Verifies that a request for the multi-factor class by a password-only session needs a second factor.
     */
    @Test
    void convert_whenMultiFactorIsRequestedAndNotReached_throwsSecondFactorRequiredException() {
        signIn(passwordOnly());
        final var request = request(null, AuthenticationContextClass.MULTI_FACTOR);

        assertThrows(SecondFactorRequiredException.class, () -> converter.convert(request));
    }

    /**
     * Verifies that a multi-factor session satisfies a request for the multi-factor class.
     */
    @Test
    void convert_whenMultiFactorIsReached_returnsNull() {
        signIn(multiFactor());

        assertNull(converter.convert(request(null, AuthenticationContextClass.MULTI_FACTOR)));
    }

    /**
     * Verifies that a password-only session satisfies a request that also accepts the password class.
     */
    @Test
    void convert_whenPasswordClassIsAlsoAccepted_returnsNull() {
        signIn(passwordOnly());

        assertNull(converter.convert(request(null,
                AuthenticationContextClass.MULTI_FACTOR + "  " + AuthenticationContextClass.PASSWORD)));
    }

    /**
     * Verifies that unknown classes are ignored.
     */
    @Test
    void convert_whenAcrValuesAreUnknown_returnsNull() {
        signIn(passwordOnly());

        assertNull(converter.convert(request(null, "urn:other:acr")));
        assertNull(converter.convert(request(null, " ")));
    }

    /**
     * Builds a request with the step-up parameters.
     *
     * @param maxAge    the {@code max_age}, may be {@code null}.
     * @param acrValues the {@code acr_values}, may be {@code null}.
     * @return the request.
     */
    private static MockHttpServletRequest request(final String maxAge, final String acrValues) {
        final var request = new MockHttpServletRequest();
        if (maxAge != null) {
            request.setParameter(StepUpAuthorizationRequestConverter.MAX_AGE_PARAMETER, maxAge);
        }
        if (acrValues != null) {
            request.setParameter(StepUpAuthorizationRequestConverter.ACR_VALUES_PARAMETER, acrValues);
        }
        return request;
    }

    /**
     * Builds a user who presented only the password {@link #AGE_SECONDS} seconds ago.
     *
     * @return the authentication.
     */
    private static UsernamePasswordAuthenticationToken passwordOnly() {
        return UsernamePasswordAuthenticationToken.authenticated("alice", null,
                List.<GrantedAuthority>of(FactorGrantedAuthority.withAuthority(PASSWORD_AUTHORITY)
                        .issuedAt(NOW.minusSeconds(AGE_SECONDS)).build()));
    }

    /**
     * Builds a user who presented the password and a second factor, both {@link #AGE_SECONDS} seconds ago.
     *
     * @return the authentication.
     */
    private static UsernamePasswordAuthenticationToken multiFactor() {
        final var issuedAt = NOW.minusSeconds(AGE_SECONDS);
        return UsernamePasswordAuthenticationToken.authenticated("alice", null, List.<GrantedAuthority>of(
                FactorGrantedAuthority.withAuthority(PASSWORD_AUTHORITY).issuedAt(issuedAt).build(),
                FactorGrantedAuthority.withAuthority(TOTP_AUTHORITY).issuedAt(issuedAt).build()));
    }

    /**
     * Makes a user the current authentication.
     *
     * @param authentication the user.
     */
    private static void signIn(final UsernamePasswordAuthenticationToken authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
