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
import com.irurueta.authserver.authorization.application.social.LockSignInMethodsUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.social.FederatedLinkingPolicy;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateNotFoundException;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// tag::x509-unbind-use-case[]
/**
 * Use case that unbinds a client certificate from an account and audits it. Like unlinking an identity, it refuses to
 * remove the last way to sign in, counted under the lock of {@link LockSignInMethodsUseCase} so that concurrent
 * removals of the same account are serialized.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class UnbindCertificateUseCase {

    /** Port that stores the bindings. */
    private final CertificateBindingRepository certificateBindingRepository;

    /** Locks and counts the sign-in methods of the account. */
    private final LockSignInMethodsUseCase lockSignInMethodsUseCase;

    /** Rules of removing a sign-in method. */
    private final FederatedLinkingPolicy federatedLinkingPolicy;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /**
     * Unbinds a certificate; a certificate of another account is never touched.
     *
     * @param userId   identifier of the account.
     * @param username name of the account, for the audit log.
     * @param id       identifier of the binding.
     * @throws CertificateNotFoundException if the account has no such binding.
     * @throws LastSignInMethodException    if the certificate is the last way the account can sign in.
     */
    public void execute(final UUID userId, final String username, final UUID id) {
        final var methods = lockSignInMethodsUseCase.execute(userId);
        if (certificateBindingRepository.findByUser(userId).stream().noneMatch(binding -> binding.id().equals(id))) {
            throw new CertificateNotFoundException("The account has no certificate " + id);
        }
        if (!federatedLinkingPolicy.mayUnlink(methods.withoutCertificate())) {
            throw new LastSignInMethodException("The certificate is the last way to sign in to the account");
        }
        if (!certificateBindingRepository.delete(id, userId)) {
            throw new CertificateNotFoundException("The account has no certificate " + id);
        }
        recordSecurityEventUseCase.execute(SecurityEventType.CERTIFICATE_UNBOUND, userId, username, id.toString());
    }
}
// end::x509-unbind-use-case[]
