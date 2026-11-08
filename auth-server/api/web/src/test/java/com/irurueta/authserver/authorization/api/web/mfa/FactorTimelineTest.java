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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Unit tests of {@link FactorTimeline}, over a real registry and the real policy (test data, not doubles).
 */
class FactorTimelineTest {

    /** Authority of the primary factor (the password). */
    private static final String PRIMARY = "FACTOR_PASSWORD";

    /** Authority of the passkey factor. */
    private static final String PASSKEY = "FACTOR_WEBAUTHN";

    /** Authority of a strong factor that proves a multi-factor authentication alone (a trusted provider's MFA). */
    private static final String FEDERATED_MFA = "FACTOR_FEDERATED_MFA";

    /** Authority of the TOTP factor. */
    private static final String TOTP = "FACTOR_TOTP";

    /** Authority of the trusted-device factor. */
    private static final String TRUSTED_DEVICE = "FACTOR_TRUSTED_DEVICE";

    /** Instant the password was presented. */
    private static final Instant PASSWORD_TIME = Instant.parse("2026-01-01T10:00:00Z");

    /** Instant the second factor was presented. */
    private static final Instant TOTP_TIME = Instant.parse("2026-01-01T10:01:00Z");

    /** Instant the trusted device was recognised. */
    private static final Instant DEVICE_TIME = Instant.parse("2026-01-01T09:00:00Z");

    /** Timeline under test. */
    private final FactorTimeline timeline = new FactorTimeline(new AuthenticationFactorRegistry(List.of(
            new AuthenticationFactor("password", "pwd", PRIMARY, FactorStrength.PRIMARY),
            new AuthenticationFactor("passkey", "hwk", PASSKEY, FactorStrength.PRIMARY_STRONG),
            new AuthenticationFactor("federated-mfa", "fed", FEDERATED_MFA, FactorStrength.PRIMARY_STRONG, true),
            new AuthenticationFactor("totp", "otp", TOTP, FactorStrength.SECOND),
            new AuthenticationFactor("trusted-device", "trusted-device", TRUSTED_DEVICE,
                    FactorStrength.REMEMBERED))), new MfaPolicy());

    /**
     * Verifies that a remembered device is not counted, while the password and a second factor are, oldest first.
     */
    @Test
    void countedFactors_whenATrustedDeviceIsPresent_leavesItOut() {
        final var user = user(factor(TOTP, TOTP_TIME), factor(TRUSTED_DEVICE, DEVICE_TIME),
                factor(PRIMARY, PASSWORD_TIME), new SimpleGrantedAuthority("ROLE_USER"));

        assertEquals(List.of(PRIMARY, TOTP), timeline.countedFactors(user).stream()
                .map(FactorGrantedAuthority::getAuthority).toList());
        assertEquals(List.of("pwd", "otp"), timeline.amrValues(user));
        assertTrue(timeline.isMultiFactor(user));
    }

    /**
     * Verifies that a password plus a trusted device is not multi-factor.
     */
    @Test
    void isMultiFactor_whenOnlyPasswordAndTrustedDevice_returnsFalse() {
        assertFalse(timeline.isMultiFactor(user(factor(PRIMARY, PASSWORD_TIME), factor(TRUSTED_DEVICE,
                DEVICE_TIME))));
    }

    /**
     * Verifies that a factor that proves a multi-factor authentication alone makes the session multi-factor.
     */
    @Test
    void isMultiFactor_whenOnlyAFactorThatIsMultiFactorAlone_returnsTrue() {
        assertTrue(timeline.isMultiFactor(user(factor(FEDERATED_MFA, PASSWORD_TIME))));
    }

    /**
     * Verifies that a strong factor that proves one thing (a passkey) is not multi-factor alone, although it satisfies
     * the sign-in policy, and is with a second factor.
     */
    @Test
    void isMultiFactor_whenOnlyAStrongSingleFactor_returnsFalse() {
        assertFalse(timeline.isMultiFactor(user(factor(PASSKEY, PASSWORD_TIME))));
        assertTrue(timeline.isMultiFactor(user(factor(PASSKEY, PASSWORD_TIME), factor(TOTP, TOTP_TIME))));
    }

    /**
     * Verifies that the time of the authentication is that of the primary factor, not of the later second one, nor of
     * an earlier remembered device.
     */
    @Test
    void authTime_whenPrimaryAndSecondFactors_returnsThePrimaryTime() {
        final var user = user(factor(TOTP, TOTP_TIME), factor(PRIMARY, PASSWORD_TIME),
                factor(TRUSTED_DEVICE, DEVICE_TIME));

        assertEquals(Optional.of(PASSWORD_TIME), timeline.authTime(user));
    }

    /**
     * Verifies that the earliest primary factor wins when there are several.
     */
    @Test
    void authTime_whenTwoPrimaryFactors_returnsTheEarliest() {
        assertEquals(Optional.of(PASSWORD_TIME),
                timeline.authTime(user(factor(PASSKEY, TOTP_TIME), factor(PRIMARY, PASSWORD_TIME))));
    }

    /**
     * Verifies that, without a primary factor, the earliest counted factor is used.
     */
    @Test
    void authTime_whenNoPrimaryFactor_returnsTheEarliestCountedFactor() {
        assertEquals(Optional.of(TOTP_TIME),
                timeline.authTime(user(factor(TOTP, TOTP_TIME), factor(TRUSTED_DEVICE, DEVICE_TIME))));
    }

    /**
     * Verifies that an authentication with no counted factor has no time.
     */
    @Test
    void authTime_whenNoCountedFactor_returnsEmpty() {
        assertTrue(timeline.authTime(user(factor(TRUSTED_DEVICE, DEVICE_TIME),
                new SimpleGrantedAuthority("ROLE_USER"))).isEmpty());
        assertTrue(timeline.amrValues(user()).isEmpty());
    }

    /**
     * Builds an authentication with authorities.
     *
     * @param authorities the authorities.
     * @return the authentication.
     */
    private static Authentication user(final GrantedAuthority... authorities) {
        return new TestingAuthenticationToken("alice", null, List.of(authorities));
    }

    /**
     * Builds a factor authority.
     *
     * @param authority the authority.
     * @param issuedAt  the instant it was granted.
     * @return the factor authority.
     */
    private static FactorGrantedAuthority factor(final String authority, final Instant issuedAt) {
        return FactorGrantedAuthority.withAuthority(authority).issuedAt(issuedAt).build();
    }
}
