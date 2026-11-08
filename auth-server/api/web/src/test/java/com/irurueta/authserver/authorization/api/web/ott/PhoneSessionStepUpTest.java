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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.AuthenticationFactorRegistry;
import com.irurueta.authserver.authorization.api.web.mfa.FactorTimeline;
import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.MfaProperties;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/** Unit tests of {@link PhoneSessionStepUp}. */
@ExtendWith(MockitoExtension.class)
class PhoneSessionStepUpTest {

    /** Maximum age of a sign-in, in minutes. */
    private static final int MAX_AGE_MINUTES = 5;

    /** Failed attempts tolerated. */
    private static final int MAX_FAILED_ATTEMPTS = 5;

    /** Days a trusted device lasts. */
    private static final int TRUSTED_DAYS = 30;

    /** Lockout, in minutes. */
    private static final int LOCKOUT_MINUTES = 15;

    /** Authority of the strong federated factor, multi-factor alone. */
    private static final String FEDERATED_MFA = "FACTOR_FEDERATED_MFA";

    /** Authority of the passkey factor, strong but a single factor. */
    private static final String PASSKEY = "FACTOR_WEBAUTHN";

    /** The instant of the clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** The session. */
    private final UsernamePasswordAuthenticationToken session =
            UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());

    /** Tells whether the account has a second factor. */
    @Mock
    private HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Reads the factors of the session. */
    @Mock
    private FactorTimeline factorTimeline;

    /** Rule under test. */
    private PhoneSessionStepUp stepUp;

    /** Creates the rule over a fixed clock. */
    @BeforeEach
    void setUp() {
        stepUp = new PhoneSessionStepUp(hasConfirmedSecondFactorUseCase, factorTimeline, properties(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    /** An account without a second factor cannot step up, so it is not asked to. */
    @Test
    void isSatisfied_whenTheAccountHasNoSecondFactor_isTrue() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(false);

        assertTrue(stepUp.isSatisfied(userId, session));
        verifyNoInteractions(factorTimeline);
    }

    /** A session with one factor is not enough for an account that has a second factor. */
    @Test
    void isSatisfied_whenTheSessionIsNotMultiFactor_isFalse() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        when(factorTimeline.isMultiFactor(session)).thenReturn(false);

        assertFalse(stepUp.isSatisfied(userId, session));
    }

    /** A recent multi-factor sign-in is enough. */
    @Test
    void isSatisfied_whenTheMultiFactorSignInIsRecent_isTrue() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        when(factorTimeline.isMultiFactor(session)).thenReturn(true);
        when(factorTimeline.authTime(session)).thenReturn(Optional.of(NOW.minus(Duration.ofMinutes(1))));

        assertTrue(stepUp.isSatisfied(userId, session));
    }

    /** An old multi-factor sign-in is not enough. */
    @Test
    void isSatisfied_whenTheMultiFactorSignInIsOld_isFalse() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        when(factorTimeline.isMultiFactor(session)).thenReturn(true);
        when(factorTimeline.authTime(session))
                .thenReturn(Optional.of(NOW.minus(Duration.ofMinutes(MAX_AGE_MINUTES + 1))));

        assertFalse(stepUp.isSatisfied(userId, session));
    }

    /** A sign-in in the future is not trusted. */
    @Test
    void isSatisfied_whenTheSignInIsInTheFuture_isFalse() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        when(factorTimeline.isMultiFactor(session)).thenReturn(true);
        when(factorTimeline.authTime(session)).thenReturn(Optional.of(NOW.plusSeconds(1)));

        assertFalse(stepUp.isSatisfied(userId, session));
    }

    /** A session that carries no instant is not trusted. */
    @Test
    void isSatisfied_whenThereIsNoSignInInstant_isFalse() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        when(factorTimeline.isMultiFactor(session)).thenReturn(true);
        when(factorTimeline.authTime(session)).thenReturn(Optional.empty());

        assertFalse(stepUp.isSatisfied(userId, session));
    }

    /**
     * Pins how the shared multi-factor rule reaches the phone page, over the real timeline: a recent sign-in at a
     * provider trusted for its multi-factor authentication is enough on its own, a passkey alone is not.
     */
    @Test
    void isSatisfied_whenTheSessionHoldsOneStrongFactor_followsTheMultiFactorRule() {
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        final var registry = new AuthenticationFactorRegistry(List.of(
                new AuthenticationFactor("federated-mfa", "fed", FEDERATED_MFA, FactorStrength.PRIMARY_STRONG, true),
                new AuthenticationFactor("passkey", "hwk", PASSKEY, FactorStrength.PRIMARY_STRONG)));
        final var realRule = new PhoneSessionStepUp(hasConfirmedSecondFactorUseCase,
                new FactorTimeline(registry, new MfaPolicy()), properties(), Clock.fixed(NOW, ZoneOffset.UTC));

        assertTrue(realRule.isSatisfied(userId, signedInWith(FEDERATED_MFA)));
        assertFalse(realRule.isSatisfied(userId, signedInWith(PASSKEY)));
    }

    /**
     * Builds a session that presented one factor a minute ago.
     *
     * @param authority the authority of the factor.
     * @return the session.
     */
    private static UsernamePasswordAuthenticationToken signedInWith(final String authority) {
        return UsernamePasswordAuthenticationToken.authenticated("alice", null, List.<GrantedAuthority>of(
                FactorGrantedAuthority.withAuthority(authority).issuedAt(NOW.minus(Duration.ofMinutes(1))).build()));
    }

    /**
     * Builds the multi-factor settings of the tests.
     *
     * @return the settings.
     */
    private static MfaProperties properties() {
        return new MfaProperties(MAX_FAILED_ATTEMPTS, Duration.ofMinutes(LOCKOUT_MINUTES),
                Duration.ofDays(TRUSTED_DAYS), "Issuer", Duration.ofMinutes(MAX_AGE_MINUTES));
    }
}
