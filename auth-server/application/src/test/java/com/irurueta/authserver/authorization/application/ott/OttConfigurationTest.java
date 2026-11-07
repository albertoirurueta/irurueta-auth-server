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

package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import com.irurueta.authserver.authorization.domain.ott.OttKind;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link OttConfiguration}.
 */
class OttConfigurationTest {

    /** Code length of the settings. */
    private static final int LENGTH = 8;

    /** Attempts of the settings. */
    private static final int ATTEMPTS = 3;

    /** Code validity of the settings. */
    private static final Duration CODE_TTL = Duration.ofMinutes(4);

    /** Link validity of the settings. */
    private static final Duration LINK_TTL = Duration.ofMinutes(9);

    /** Configuration under test. */
    private final OttConfiguration configuration = new OttConfiguration();

    /**
     * Verifies that the policy takes its values from the settings.
     */
    @Test
    void ottPolicy_whenSettingsAreGiven_buildsPolicyFromThem() {
        final var policy = configuration.ottPolicy(new OttProperties(LENGTH, CODE_TTL, LINK_TTL, ATTEMPTS));

        assertEquals(LENGTH, policy.codeLength());
        assertEquals(CODE_TTL, policy.ttl(OttKind.CODE));
        assertEquals(LINK_TTL, policy.ttl(OttKind.LINK));
        assertEquals(ATTEMPTS, policy.maxAttempts());
    }

    /**
     * Verifies the type of the generator.
     */
    @Test
    void oneTimeCodeGenerator_whenCalled_returnsSecureRandomGenerator() {
        assertInstanceOf(SecureRandomOneTimeCodeGenerator.class, configuration.oneTimeCodeGenerator());
    }

    /**
     * Verifies the type of the hasher.
     */
    @Test
    void oneTimeCodeHasher_whenCalled_returnsSha256Hasher() {
        assertInstanceOf(Sha256OneTimeCodeHasher.class, configuration.oneTimeCodeHasher());
    }
}
