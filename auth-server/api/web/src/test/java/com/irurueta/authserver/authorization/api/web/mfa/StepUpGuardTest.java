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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.MfaProperties;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Unit tests of {@link StepUpGuard}.
 */
@ExtendWith(MockitoExtension.class)
class StepUpGuardTest {

    /** Current instant of the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");

    /** Maximum age of the step-up, in minutes. */
    private static final int MAX_AGE_MINUTES = 5;

    /** Consecutive failures that lock the second factor; irrelevant here but required by the settings. */
    private static final int MAX_FAILED_ATTEMPTS = 3;

    /** Seconds within the maximum age. */
    private static final long RECENT_SECONDS = 60;

    /** Seconds beyond the maximum age. */
    private static final long OLD_SECONDS = 600;

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Tells whether the account has a confirmed second factor. */
    @Mock
    private HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Guard under test. */
    private StepUpGuard guard;

    /**
     * Builds the guard over a fixed clock and a five-minute maximum age.
     */
    @BeforeEach
    void setUp() {
        guard = new StepUpGuard(hasConfirmedSecondFactorUseCase,
                new MfaProperties(MAX_FAILED_ATTEMPTS, Duration.ofMinutes(MAX_AGE_MINUTES),
                        Duration.ofMinutes(MAX_AGE_MINUTES), "Issuer", Duration.ofMinutes(MAX_AGE_MINUTES)),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    /**
     * Clears the security context.
     */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that an account without a second factor is never asked to step up.
     */
    @Test
    void requireRecentMultiFactor_whenAccountHasNoSecondFactor_passes() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(false);
        signIn(AuthenticationContextClass.PASSWORD, null);

        assertDoesNotThrow(() -> guard.requireRecentMultiFactor(userId));
    }

    /**
     * Verifies that a recent multi-factor sign-in passes.
     */
    @Test
    void requireRecentMultiFactor_whenTokenShowsARecentMultiFactorSignIn_passes() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        signIn(AuthenticationContextClass.MULTI_FACTOR, NOW.minusSeconds(RECENT_SECONDS));

        assertDoesNotThrow(() -> guard.requireRecentMultiFactor(userId));
    }

    /**
     * Verifies that a password-only sign-in must step up, and the exception says how.
     */
    @Test
    void requireRecentMultiFactor_whenTokenIsPasswordOnly_throwsInsufficientUserAuthenticationException() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        signIn(AuthenticationContextClass.PASSWORD, NOW.minusSeconds(RECENT_SECONDS));

        final var error = assertThrows(InsufficientUserAuthenticationException.class,
                () -> guard.requireRecentMultiFactor(userId));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, error.getAcrValues());
        assertEquals(Duration.ofMinutes(MAX_AGE_MINUTES), error.getMaxAge());
    }

    /**
     * Verifies that an old multi-factor sign-in must step up.
     */
    @Test
    void requireRecentMultiFactor_whenSignInIsTooOld_throwsInsufficientUserAuthenticationException() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        signIn(AuthenticationContextClass.MULTI_FACTOR, NOW.minusSeconds(OLD_SECONDS));

        assertThrows(InsufficientUserAuthenticationException.class, () -> guard.requireRecentMultiFactor(userId));
    }

    /**
     * Verifies that a multi-factor token without {@code auth_time}, or with one in the future, must step up.
     */
    @Test
    void requireRecentMultiFactor_whenAuthTimeIsMissingOrInTheFuture_throwsInsufficientUserAuthenticationException() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);

        signIn(AuthenticationContextClass.MULTI_FACTOR, null);
        assertThrows(InsufficientUserAuthenticationException.class, () -> guard.requireRecentMultiFactor(userId));
        signIn(AuthenticationContextClass.MULTI_FACTOR, NOW.plusSeconds(RECENT_SECONDS));
        assertThrows(InsufficientUserAuthenticationException.class, () -> guard.requireRecentMultiFactor(userId));
    }

    /**
     * Verifies that an authentication that is not a bearer token must step up.
     */
    @Test
    void requireRecentMultiFactor_whenAuthenticationIsNotABearerToken_throwsInsufficientUserAuthenticationException() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()));

        assertThrows(InsufficientUserAuthenticationException.class, () -> guard.requireRecentMultiFactor(userId));
    }

    /**
     * Makes a bearer token the current authentication.
     *
     * @param acr      the {@code acr} claim.
     * @param authTime the {@code auth_time} claim, or {@code null} to leave it out.
     */
    private static void signIn(final String acr, final Instant authTime) {
        final var builder = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice")
                .claim(IdTokenClaimNames.ACR, acr);
        if (authTime != null) {
            builder.claim(IdTokenClaimNames.AUTH_TIME, authTime.getEpochSecond());
        }
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(builder.build()));
    }
}
