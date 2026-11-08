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

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * The binding of a client certificate to an account: the certificate is recognised by the SHA-256 fingerprint of its
 * encoded form, never by its subject, which anyone can choose.
 *
 * @param id                identifier of the binding.
 * @param userId            identifier of the account (the {@code users} row).
 * @param fingerprintSha256 SHA-256 fingerprint of the DER-encoded certificate, as 64 lower case hexadecimal digits.
 * @param subjectDn         subject distinguished name of the certificate, kept to tell the bindings apart.
 * @param createdAt         instant at which the certificate was bound.
 */
public record CertificateBinding(
        UUID id,
        UUID userId,
        String fingerprintSha256,
        String subjectDn,
        Instant createdAt) {

    /** Number of hexadecimal digits of a SHA-256 fingerprint. */
    public static final int FINGERPRINT_LENGTH = 64;

    /** Shape of a fingerprint: lower case hexadecimal digits only. */
    private static final Pattern FINGERPRINT = Pattern.compile("[0-9a-f]{" + FINGERPRINT_LENGTH + "}");

    /**
     * Validates the binding.
     *
     * @throws IllegalArgumentException if the id, the account or the creation instant is missing, the fingerprint is
     *                                  not 64 lower case hexadecimal digits, or the subject is blank.
     */
    public CertificateBinding {
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        if (userId == null) {
            throw new IllegalArgumentException("userId must not be null");
        }
        requireText(fingerprintSha256, "fingerprintSha256");
        if (!FINGERPRINT.matcher(fingerprintSha256).matches()) {
            throw new IllegalArgumentException("fingerprintSha256 must be " + FINGERPRINT_LENGTH
                    + " lower case hexadecimal digits");
        }
        requireText(subjectDn, "subjectDn");
        if (createdAt == null) {
            throw new IllegalArgumentException("createdAt must not be null");
        }
    }
}
