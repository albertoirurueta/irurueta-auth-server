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
package com.irurueta.authserver.authorization.domain.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link CertificateBinding}.
 */
class CertificateBindingTest {

    /** Binding identifier used by the tests. */
    private static final UUID ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    /** Account identifier used by the tests. */
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000002");

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "ab".repeat(CertificateBinding.FINGERPRINT_LENGTH / 2);

    /** Subject used by the tests. */
    private static final String SUBJECT_DN = "CN=alice,O=Example";

    /** Creation instant used by the tests. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var binding = new CertificateBinding(ID, USER_ID, FINGERPRINT, SUBJECT_DN, CREATED_AT);

        assertEquals(ID, binding.id());
        assertEquals(USER_ID, binding.userId());
        assertEquals(FINGERPRINT, binding.fingerprintSha256());
        assertEquals(SUBJECT_DN, binding.subjectDn());
        assertEquals(CREATED_AT, binding.createdAt());
    }

    /**
     * Verifies that a missing id is rejected.
     */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateBinding(null, USER_ID, FINGERPRINT, SUBJECT_DN, CREATED_AT));
    }

    /**
     * Verifies that a missing account is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateBinding(ID, null, FINGERPRINT, SUBJECT_DN, CREATED_AT));
    }

    /**
     * Verifies that a blank fingerprint is rejected.
     */
    @Test
    void constructor_whenFingerprintIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateBinding(ID, USER_ID, " ", SUBJECT_DN, CREATED_AT));
    }

    /**
     * Verifies that a fingerprint of the wrong length is rejected.
     */
    @Test
    void constructor_whenFingerprintIsTooShort_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateBinding(ID, USER_ID, "abcd", SUBJECT_DN, CREATED_AT));
    }

    /**
     * Verifies that a fingerprint in upper case or with other characters is rejected.
     */
    @Test
    void constructor_whenFingerprintIsNotLowerCaseHex_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateBinding(ID, USER_ID, FINGERPRINT.toUpperCase(Locale.ROOT),
                        SUBJECT_DN, CREATED_AT));
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateBinding(ID, USER_ID, "z".repeat(CertificateBinding.FINGERPRINT_LENGTH),
                        SUBJECT_DN, CREATED_AT));
    }

    /**
     * Verifies that a blank subject is rejected.
     */
    @Test
    void constructor_whenSubjectDnIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateBinding(ID, USER_ID, FINGERPRINT, " ", CREATED_AT));
    }

    /**
     * Verifies that a missing creation instant is rejected.
     */
    @Test
    void constructor_whenCreatedAtIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateBinding(ID, USER_ID, FINGERPRINT, SUBJECT_DN, null));
    }

    /**
     * Verifies the value semantics.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var first = new CertificateBinding(ID, USER_ID, FINGERPRINT, SUBJECT_DN, CREATED_AT);
        final var second = new CertificateBinding(ID, USER_ID, FINGERPRINT, SUBJECT_DN, CREATED_AT);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first, new CertificateBinding(ID, USER_ID, FINGERPRINT, "CN=bob", CREATED_AT));
    }
}
