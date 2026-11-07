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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.testsupport.TestCertificates;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PemCertificateReader}, with certificates generated at run time.
 */
class PemCertificateReaderTest {

    /** A valid certificate. */
    private static TestCertificates.GeneratedCertificate valid;

    /** A second valid certificate. */
    private static TestCertificates.GeneratedCertificate other;

    /** Reader under test. */
    private final PemCertificateReader reader = new PemCertificateReader();

    /**
     * Generates the certificates.
     */
    @BeforeAll
    static void generateCertificates() {
        valid = TestCertificates.generate("alice-" + UUID.randomUUID());
        other = TestCertificates.generate("bob-" + UUID.randomUUID());
    }

    /**
     * Verifies that a PEM certificate is read into the fingerprint the sign-in computes and its subject.
     */
    @Test
    void read_whenTheCertificateIsValid_returnsItsFingerprintAndSubject() {
        final var read = reader.read(valid.pem());

        assertEquals(valid.fingerprintSha256(), read.fingerprintSha256());
        assertEquals(valid.certificate().getSubjectX500Principal().getName(), read.subjectDn());
    }

    /**
     * Verifies that an expired certificate is refused.
     */
    @Test
    void read_whenTheCertificateExpired_throwsInvalidCertificateException() {
        final var expired = TestCertificates.generateExpired("old-" + UUID.randomUUID());

        assertThrows(InvalidCertificateException.class, () -> reader.read(expired.pem()));
    }

    /**
     * Verifies that a value that is not a certificate is refused.
     */
    @Test
    void read_whenTheValueIsNotACertificate_throwsInvalidCertificateException() {
        assertThrows(InvalidCertificateException.class, () -> reader.read("not a certificate"));
    }

    /**
     * Verifies that two certificates in one value are refused.
     */
    @Test
    void read_whenTheValueHoldsTwoCertificates_throwsInvalidCertificateException() {
        assertThrows(InvalidCertificateException.class, () -> reader.read(valid.pem() + other.pem()));
    }

    /**
     * Verifies that an empty PEM text, which holds no certificate, is refused.
     */
    @Test
    void read_whenTheValueHoldsNoCertificate_throwsInvalidCertificateException() {
        assertThrows(InvalidCertificateException.class, () -> reader.read(""));
    }

    /**
     * Verifies that a value that carries a private key is refused without being parsed, and that a missing value is
     * refused.
     */
    @Test
    void read_whenTheValueCarriesAPrivateKey_throwsInvalidCertificateException() {
        final var withKey = valid.pem() + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";

        assertThrows(InvalidCertificateException.class, () -> reader.read(withKey));
        assertThrows(InvalidCertificateException.class, () -> reader.read(null));
    }

    /**
     * Verifies that a subject longer than the table keeps is refused.
     */
    @Test
    void read_whenTheSubjectIsTooLong_throwsInvalidCertificateException() {
        final var longName = TestCertificates.generate("x".repeat(PemCertificateReader.MAX_SUBJECT_LENGTH));

        assertThrows(InvalidCertificateException.class, () -> reader.read(longName.pem()));
    }
}
