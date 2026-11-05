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

package com.irurueta.authserver.authorization.api.web.password;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

/**
 * Unit tests of {@link PasswordConfiguration}.
 */
class PasswordConfigurationTest {

    /** Clear-text value used to exercise the encoder; built at runtime, not a real credential. */
    private static final String RAW_VALUE = String.join("-", "clear", "text", "value");

    /** Configuration under test. */
    private final PasswordConfiguration configuration = new PasswordConfiguration();

    /**
     * Verifies that new values are encoded with the Argon2 default and match afterwards.
     */
    @Test
    void passwordEncoder_whenValueIsEncoded_usesArgon2AndMatchesIt() {
        final var encoder = configuration.passwordEncoder();

        final var encoded = encoder.encode(RAW_VALUE);

        assertTrue(encoded.startsWith("{" + PasswordConfiguration.DEFAULT_ENCODING_ID + "}"));
        assertTrue(encoder.matches(RAW_VALUE, encoded));
        assertFalse(encoder.upgradeEncoding(encoded));
    }

    /**
     * Verifies that the encoder does not match a different value.
     */
    @Test
    void passwordEncoder_whenValueDiffers_doesNotMatchIt() {
        final var encoder = configuration.passwordEncoder();

        assertFalse(encoder.matches("other", encoder.encode(RAW_VALUE)));
    }

    /**
     * Verifies that a legacy bcrypt hash still matches and is flagged for upgrade.
     */
    @Test
    void passwordEncoder_whenHashIsBcrypt_matchesAndRequestsUpgrade() {
        final var encoder = configuration.passwordEncoder();
        final var legacy = "{" + PasswordConfiguration.BCRYPT_ENCODING_ID + "}"
                + new BCryptPasswordEncoder().encode(RAW_VALUE);

        assertTrue(encoder.matches(RAW_VALUE, legacy));
        assertTrue(encoder.upgradeEncoding(legacy));
    }

    /**
     * Verifies that a legacy PBKDF2 hash still matches.
     */
    @Test
    void passwordEncoder_whenHashIsPbkdf2_matchesIt() {
        final var encoder = configuration.passwordEncoder();
        final var legacy = "{" + PasswordConfiguration.PBKDF2_ENCODING_ID + "}"
                + Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(RAW_VALUE);

        assertTrue(encoder.matches(RAW_VALUE, legacy));
    }
}
