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
package com.irurueta.authserver.authorization.domain.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ProviderTrust}.
 */
class ProviderTrustTest {

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var trust = new ProviderTrust(IdentityProvider.MICROSOFT, true);

        assertEquals(IdentityProvider.MICROSOFT, trust.provider());
        assertTrue(trust.trustMfa());
    }

    /**
     * Verifies that a missing provider is rejected.
     */
    @Test
    void constructor_whenProviderIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new ProviderTrust(null, false));
    }

    /**
     * Verifies that a trusted provider that reports mfa is strong.
     */
    @Test
    void isStrong_whenTrustedAndAmrContainsMfa_isTrue() {
        assertTrue(new ProviderTrust(IdentityProvider.GOOGLE, true).isStrong(List.of("pwd", "mfa")));
    }

    /**
     * Verifies that a provider that is not trusted is never strong.
     */
    @Test
    void isStrong_whenNotTrusted_isFalse() {
        assertFalse(new ProviderTrust(IdentityProvider.GOOGLE, false).isStrong(List.of("pwd", "mfa")));
    }

    /**
     * Verifies that a trusted provider that does not report mfa is not strong.
     */
    @Test
    void isStrong_whenAmrLacksMfa_isFalse() {
        assertFalse(new ProviderTrust(IdentityProvider.GOOGLE, true).isStrong(List.of("pwd")));
    }

    /**
     * Verifies that a trusted provider that reports nothing is not strong.
     */
    @Test
    void isStrong_whenAmrIsMissing_isFalse() {
        final var trust = new ProviderTrust(IdentityProvider.GOOGLE, true);

        assertFalse(trust.isStrong(null));
        assertFalse(trust.isStrong(List.of()));
    }

    /**
     * Verifies that a null element of the reported values is ignored.
     */
    @Test
    void isStrong_whenAmrHoldsNull_ignoresIt() {
        final var trust = new ProviderTrust(IdentityProvider.GOOGLE, true);

        assertTrue(trust.isStrong(Arrays.asList(null, "mfa")));
        assertFalse(trust.isStrong(Arrays.asList(null, "pwd")));
    }

    /**
     * Verifies the value semantics.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var first = new ProviderTrust(IdentityProvider.APPLE, true);
        final var second = new ProviderTrust(IdentityProvider.APPLE, true);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first, new ProviderTrust(IdentityProvider.APPLE, false));
    }
}
