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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import org.springframework.stereotype.Component;

// tag::x509-pem-reader[]
/**
 * Reads the certificate sent to bind it to an account: exactly one X.509 certificate in PEM form, within its validity
 * period, with a subject. A value that carries a private key is refused without being parsed: only the public
 * certificate is ever sent. The fingerprint is computed exactly as {@link CertificatePrincipalExtractor} computes it at
 * sign-in, so the binding matches the certificate the browser presents later.
 */
@Component
public class PemCertificateReader {

    /** Longest subject the {@code x509_certificates} table keeps. */
    static final int MAX_SUBJECT_LENGTH = 1000;

    /** Type of the certificates. */
    private static final String CERTIFICATE_TYPE = "X.509";

    /** Marker of a PEM private key, of any algorithm. */
    private static final String PRIVATE_KEY_MARKER = "PRIVATE KEY";

    /** Computes the fingerprint the sign-in looks up. */
    private final CertificatePrincipalExtractor fingerprints = new CertificatePrincipalExtractor();

    /**
     * Reads a certificate.
     *
     * @param pem the certificate in PEM form.
     * @return its fingerprint and subject.
     * @throws InvalidCertificateException if the value carries a private key, is not exactly one X.509 certificate, is
     *                                     outside its validity period or has no usable subject.
     */
    public PresentedCertificate read(final String pem) {
        if (pem == null || pem.contains(PRIVATE_KEY_MARKER)) {
            throw new InvalidCertificateException("Only a public certificate may be sent");
        }
        final var certificate = parse(pem);
        try {
            certificate.checkValidity();
        } catch (final CertificateExpiredException | CertificateNotYetValidException e) {
            throw new InvalidCertificateException("The certificate is not within its validity period", e);
        }
        final var subject = certificate.getSubjectX500Principal().getName();
        if (subject.isBlank() || subject.length() > MAX_SUBJECT_LENGTH) {
            throw new InvalidCertificateException("The certificate has no usable subject");
        }
        try {
            return new PresentedCertificate(fingerprints.fingerprintOf(certificate.getEncoded()), subject);
        } catch (final CertificateEncodingException e) {
            throw new InvalidCertificateException("The certificate cannot be encoded", e);
        }
    }

    /**
     * Parses exactly one X.509 certificate.
     *
     * @param pem the PEM text.
     * @return the certificate.
     * @throws InvalidCertificateException if the text is not exactly one X.509 certificate.
     */
    private static X509Certificate parse(final String pem) {
        try {
            final var certificates = CertificateFactory.getInstance(CERTIFICATE_TYPE)
                    .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            if (certificates.size() != 1
                    || !(certificates.iterator().next() instanceof final X509Certificate certificate)) {
                throw new InvalidCertificateException("Exactly one X.509 certificate must be sent");
            }
            return certificate;
        } catch (final CertificateException e) {
            throw new InvalidCertificateException("The value is not a PEM X.509 certificate", e);
        }
    }
}
// end::x509-pem-reader[]
