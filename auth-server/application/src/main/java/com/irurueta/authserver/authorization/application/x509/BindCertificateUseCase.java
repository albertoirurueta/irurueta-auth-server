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
package com.irurueta.authserver.authorization.application.x509;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.x509.CertificateAlreadyBoundException;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.time.Clock;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that binds a client certificate to an account and audits it. The audit detail is the fingerprint, which
 * identifies a public certificate and is not a secret.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class BindCertificateUseCase {

    /** Port that stores the bindings. */
    private final CertificateBindingRepository certificateBindingRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Binds a certificate to an account. Binding a certificate the account already has changes nothing.
     *
     * @param userId            identifier of the account.
     * @param username          name of the account, for the audit log.
     * @param fingerprintSha256 SHA-256 fingerprint of the certificate, as lower case hexadecimal digits.
     * @param subjectDn         subject distinguished name of the certificate.
     * @return the binding.
     * @throws CertificateAlreadyBoundException if the certificate is bound to another account.
     * @throws IllegalArgumentException         if the fingerprint or the subject is malformed.
     */
    public CertificateBinding execute(
            final UUID userId, final String username, final String fingerprintSha256, final String subjectDn) {
        final var binding = new CertificateBinding(UUID.randomUUID(), userId, fingerprintSha256, subjectDn,
                clock.instant());
        final var existing = certificateBindingRepository.findByFingerprintSha256(fingerprintSha256);
        if (existing.isPresent()) {
            if (existing.get().userId().equals(userId)) {
                return existing.get();
            }
            throw new CertificateAlreadyBoundException("The certificate is bound to another account");
        }
        final var stored = certificateBindingRepository.save(binding);
        recordSecurityEventUseCase.execute(SecurityEventType.CERTIFICATE_BOUND, userId, username, fingerprintSha256);
        return stored;
    }
}
