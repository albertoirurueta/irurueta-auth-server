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

import com.irurueta.authserver.authorization.api.web.mfa.AuthenticationFactorRegistry;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/** Unit tests of {@link PrimaryFactorSession}. */
class PrimaryFactorSessionTest {

    /** Rules under test, over a registry with a primary, a strong primary and a second factor. */
    private final PrimaryFactorSession session = new PrimaryFactorSession(new AuthenticationFactorRegistry(List.of(
            new AuthenticationFactor("password", "pwd", "FACTOR_PASSWORD", FactorStrength.PRIMARY),
            new AuthenticationFactor("passkey", "hwk", "FACTOR_WEBAUTHN", FactorStrength.PRIMARY_STRONG),
            new AuthenticationFactor("totp", "otp", "FACTOR_TOTP", FactorStrength.SECOND),
            new AuthenticationFactor("ott-email", "otp", "FACTOR_OTT", FactorStrength.PRIMARY))));

    /** A primary factor makes the session one. */
    @Test
    void holdsPrimaryFactor_whenAPrimaryOrStrongPrimaryFactorWasPresented_isTrue() {
        assertTrue(session.holdsPrimaryFactor(signedIn("FACTOR_PASSWORD")));
        assertTrue(session.holdsPrimaryFactor(signedIn("FACTOR_WEBAUTHN")));
    }

    /** A second factor alone, nothing, or nobody does not. */
    @Test
    void holdsPrimaryFactor_whenOnlyASecondFactorOrNothingWasPresented_isFalse() {
        assertFalse(session.holdsPrimaryFactor(signedIn("FACTOR_TOTP")));
        assertFalse(session.holdsPrimaryFactor(signedIn()));
        assertFalse(session.holdsPrimaryFactor(null));
    }

    /** The channel that signed the user in is recognised. */
    @Test
    void signedInThrough_whenTheSignInAuthorityOfTheChannelIsHeld_isTrue() {
        assertTrue(session.signedInThrough(signedIn("FACTOR_OTT"), OttChannel.EMAIL));
        assertFalse(session.signedInThrough(signedIn("FACTOR_OTT"), OttChannel.SMS));
        assertFalse(session.signedInThrough(signedIn("FACTOR_PASSWORD"), OttChannel.EMAIL));
    }

    /**
     * Builds a signed-in authentication holding factors.
     *
     * @param factors the factor authorities.
     * @return the authentication.
     */
    private static Authentication signedIn(final String... factors) {
        final var authorities = Arrays.stream(factors)
                .map(factor -> FactorGrantedAuthority.withAuthority(factor).build()).toList();
        return new TestingAuthenticationToken("alice", null, authorities);
    }
}
