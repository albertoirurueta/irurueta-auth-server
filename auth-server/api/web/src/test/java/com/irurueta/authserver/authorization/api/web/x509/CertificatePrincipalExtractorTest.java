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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.testsupport.TestCertificates;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link CertificatePrincipalExtractor}, with a certificate generated at run time.
 */
class CertificatePrincipalExtractorTest {

    /** Length of a SHA-256 fingerprint in hexadecimal digits. */
    private static final int FINGERPRINT_LENGTH = 64;

    /** A certificate generated for the run. */
    private static TestCertificates.GeneratedCertificate certificate;

    /** Extractor under test. */
    private final CertificatePrincipalExtractor extractor = new CertificatePrincipalExtractor();

    /**
     * Generates the certificate.
     */
    @BeforeAll
    static void generateCertificate() {
        certificate = TestCertificates.generate("fingerprint-test");
    }

    /**
     * Verifies that the principal is the SHA-256 fingerprint of the certificate, in lower case hexadecimal digits.
     */
    @Test
    void extractPrincipal_whenCertificateIsValid_returnsItsSha256Fingerprint() {
        final var principal = extractor.extractPrincipal(certificate.certificate());

        assertEquals(certificate.fingerprintSha256(), principal);
        assertEquals(FINGERPRINT_LENGTH, ((String) principal).length());
        assertEquals(principal.toString().toLowerCase(Locale.ROOT), principal);
    }

    /**
     * Verifies that two certificates with the same subject have different principals, as the subject name never
     * identifies a certificate.
     */
    @Test
    void extractPrincipal_whenSubjectsMatch_returnsDifferentFingerprints() {
        final var other = TestCertificates.generate("fingerprint-test");

        assertEquals(certificate.certificate().getSubjectX500Principal(),
                other.certificate().getSubjectX500Principal());
        assertEquals(false, extractor.extractPrincipal(other.certificate())
                .equals(extractor.extractPrincipal(certificate.certificate())));
    }

    /**
     * Verifies that a certificate that cannot be encoded yields a principal that no binding has.
     *
     * @throws CertificateEncodingException if the mock cannot be set up.
     */
    @Test
    void extractPrincipal_whenCertificateCannotBeEncoded_returnsTheUnreadablePrincipal()
            throws CertificateEncodingException {
        final var broken = mock(X509Certificate.class);
        when(broken.getEncoded()).thenThrow(new CertificateEncodingException("broken"));

        assertEquals(CertificatePrincipalExtractor.UNREADABLE, extractor.extractPrincipal(broken));
    }

    /**
     * Verifies that a certificate that expired yields the unreadable principal, so no binding can match it.
     */
    @Test
    void extractPrincipal_whenCertificateHasExpired_returnsTheUnreadablePrincipal() {
        final var expired = TestCertificates.generateExpired("expired-test");

        assertEquals(CertificatePrincipalExtractor.UNREADABLE, extractor.extractPrincipal(expired.certificate()));
    }

    /**
     * Verifies that a certificate that is not valid yet yields the unreadable principal.
     *
     * @throws CertificateException if the mock cannot be set up.
     */
    @Test
    void extractPrincipal_whenCertificateIsNotYetValid_returnsTheUnreadablePrincipal() throws CertificateException {
        final var early = mock(X509Certificate.class);
        doThrow(new CertificateNotYetValidException("early")).when(early).checkValidity();

        assertEquals(CertificatePrincipalExtractor.UNREADABLE, extractor.extractPrincipal(early));
    }

    /**
     * Verifies the fingerprint of raw bytes.
     */
    @Test
    void fingerprintOf_whenBytesAreGiven_returnsTheDigest() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                extractor.fingerprintOf("abc".getBytes(StandardCharsets.US_ASCII)));
    }
}
