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

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.util.Optional;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that resolves a client certificate, presented over TLS or by a trusted proxy, to the account it is bound
 * to. The certificate is recognised by its SHA-256 fingerprint only. Whether the certificate is valid (signed by a
 * trusted authority, not expired) is decided before, by the TLS layer, never here.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ResolveCertificateLoginUseCase {

    /** Shape of a fingerprint: 64 lower case hexadecimal digits. */
    private static final Pattern FINGERPRINT = Pattern.compile("[0-9a-f]{64}");

    /** Port that stores the bindings. */
    private final CertificateBindingRepository certificateBindingRepository;

    /** Port that stores the accounts. */
    private final UserAccountRepository userAccountRepository;

    /**
     * Finds the account a certificate is bound to.
     *
     * @param fingerprintSha256 SHA-256 fingerprint of the certificate, as lower case hexadecimal digits.
     * @return the account, or an empty optional when the fingerprint is malformed or not bound to any account.
     */
    public Optional<UserAccount> execute(final String fingerprintSha256) {
        if (fingerprintSha256 == null || !FINGERPRINT.matcher(fingerprintSha256).matches()) {
            return Optional.empty();
        }
        return certificateBindingRepository.findByFingerprintSha256(fingerprintSha256)
                .flatMap(binding -> userAccountRepository.findById(binding.userId()));
    }
}
