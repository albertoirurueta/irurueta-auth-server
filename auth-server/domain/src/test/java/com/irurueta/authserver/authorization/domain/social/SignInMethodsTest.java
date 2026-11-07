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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SignInMethods}.
 */
class SignInMethodsTest {

    /**
     * Verifies that there is a way to sign in when any of the four exists.
     */
    @Test
    void any_whenAMethodExists_returnsTrue() {
        assertTrue(new SignInMethods(true, 0, false, 0).any());
        assertTrue(new SignInMethods(false, 2, false, 0).any());
        assertTrue(new SignInMethods(false, 0, true, 0).any());
        assertTrue(new SignInMethods(false, 0, false, 2).any());
    }

    /**
     * Verifies that there is no way to sign in when none exists.
     */
    @Test
    void any_whenNoMethodExists_returnsFalse() {
        assertFalse(new SignInMethods(false, 0, false, 0).any());
    }

    /**
     * Verifies that removing an identity lowers its count only, never below zero.
     */
    @Test
    void withoutFederatedIdentity_whenCalled_lowersTheIdentityCount() {
        assertEquals(new SignInMethods(true, 1, true, 2),
                new SignInMethods(true, 2, true, 2).withoutFederatedIdentity());
        assertEquals(new SignInMethods(false, 0, false, 1),
                new SignInMethods(false, 0, false, 1).withoutFederatedIdentity());
    }

    /**
     * Verifies that removing a certificate lowers its count only, never below zero.
     */
    @Test
    void withoutCertificate_whenCalled_lowersTheCertificateCount() {
        assertEquals(new SignInMethods(true, 2, true, 1), new SignInMethods(true, 2, true, 2).withoutCertificate());
        assertEquals(new SignInMethods(false, 1, false, 0), new SignInMethods(false, 1, false, 0).withoutCertificate());
    }

    /**
     * Verifies the value semantics of the record.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var first = new SignInMethods(true, 1, false, 2);
        final var second = new SignInMethods(true, 1, false, 2);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
    }
}
