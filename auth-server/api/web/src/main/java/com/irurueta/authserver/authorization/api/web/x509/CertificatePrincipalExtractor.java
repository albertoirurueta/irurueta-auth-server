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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

/**
 * Takes the SHA-256 fingerprint of the client certificate as the principal, as 64 lower case hexadecimal digits, which
 * is what a binding stores and what {@code ResolveCertificateLoginUseCase} looks up. The fingerprint, and not the
 * subject name, identifies a certificate: whoever controls a CA can issue a certificate with any subject, and none
 * with a given fingerprint. A certificate that is expired or not yet valid has no principal: neither the TLS handshake
 * of the dedicated port (no authority validates the chain) nor a proxy that forwards a certificate is trusted to have
 * checked it. One extractor serves both transports, because both leave the certificate in the same
 * request attribute.
 */
@Slf4j
public class CertificatePrincipalExtractor implements X509PrincipalExtractor {

    /** Algorithm of the fingerprint. */
    private static final String ALGORITHM = "SHA-256";

    /**
     * Principal of a certificate that cannot be encoded or is expired or not yet valid: it is not a fingerprint, so it
     * is bound to no account and the sign-in fails like any unknown certificate.
     */
    static final String UNREADABLE = "";

    /**
     * Extracts the principal.
     *
     * @param certificate the client certificate.
     * @return its fingerprint, or {@link #UNREADABLE} when it cannot be encoded or is not within its validity period.
     */
    @Override
    public Object extractPrincipal(final X509Certificate certificate) {
        try {
            certificate.checkValidity();
            return fingerprintOf(certificate.getEncoded());
        } catch (final CertificateExpiredException | CertificateNotYetValidException e) {
            log.debug("The client certificate is not within its validity period", e);
            return UNREADABLE;
        } catch (final CertificateEncodingException e) {
            log.debug("The client certificate cannot be encoded", e);
            return UNREADABLE;
        }
    }

    /**
     * Computes the fingerprint of a DER encoded certificate.
     *
     * @param encoded the DER form of the certificate.
     * @return the SHA-256 digest as lower case hexadecimal digits.
     */
    public String fingerprintOf(final byte[] encoded) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance(ALGORITHM).digest(encoded));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
