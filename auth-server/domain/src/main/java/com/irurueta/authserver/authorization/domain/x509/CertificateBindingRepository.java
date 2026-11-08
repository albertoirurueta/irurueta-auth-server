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

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Port that stores the client certificates bound to accounts. It never returns {@code null}.
 */
public interface CertificateBindingRepository {

    /**
     * Finds the binding of a certificate.
     *
     * @param fingerprintSha256 SHA-256 fingerprint of the certificate, as lower case hexadecimal digits.
     * @return the binding, or an empty optional when the certificate is not bound to any account.
     */
    Optional<CertificateBinding> findByFingerprintSha256(String fingerprintSha256);

    /**
     * Lists the certificates bound to an account, oldest first.
     *
     * @param userId identifier of the account.
     * @return the bindings, possibly empty.
     */
    List<CertificateBinding> findByUser(UUID userId);

    /**
     * Stores a binding.
     *
     * @param binding binding to store.
     * @return the stored binding.
     */
    CertificateBinding save(CertificateBinding binding);

    /**
     * Deletes a binding of an account.
     *
     * @param id     identifier of the binding.
     * @param userId identifier of the account, so nobody can unbind another account's certificate.
     * @return {@code true} when a binding was deleted.
     */
    boolean delete(UUID id, UUID userId);
}
