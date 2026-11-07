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
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateNotFoundException;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that unbinds a client certificate from an account and audits it.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class UnbindCertificateUseCase {

    /** Port that stores the bindings. */
    private final CertificateBindingRepository certificateBindingRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /**
     * Unbinds a certificate; a certificate of another account is never touched.
     *
     * @param userId   identifier of the account.
     * @param username name of the account, for the audit log.
     * @param id       identifier of the binding.
     * @throws CertificateNotFoundException if the account has no such binding.
     */
    public void execute(final UUID userId, final String username, final UUID id) {
        if (!certificateBindingRepository.delete(id, userId)) {
            throw new CertificateNotFoundException("The account has no certificate " + id);
        }
        recordSecurityEventUseCase.execute(SecurityEventType.CERTIFICATE_UNBOUND, userId, username, id.toString());
    }
}
