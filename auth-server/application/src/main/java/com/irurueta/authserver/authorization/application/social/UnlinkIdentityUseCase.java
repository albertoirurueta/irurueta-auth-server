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
package com.irurueta.authserver.authorization.application.social;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityNotFoundException;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedLinkingPolicy;
import com.irurueta.authserver.authorization.domain.social.GeneratedPasswordRepository;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import com.irurueta.authserver.authorization.domain.social.SignInMethods;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that unlinks an identity of an external provider from an account and audits it. It refuses to remove the
 * last way to sign in: the account must keep a password its owner knows, another linked identity, a passkey or a bound
 * certificate.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class UnlinkIdentityUseCase {

    /** Port that stores the links. */
    private final FederatedIdentityRepository federatedIdentityRepository;

    /** Port that remembers the accounts that only hold a generated password. */
    private final GeneratedPasswordRepository generatedPasswordRepository;

    /** Port that reads the passkeys. */
    private final PasskeyRepository passkeyRepository;

    /** Port that reads the bound certificates. */
    private final CertificateBindingRepository certificateBindingRepository;

    /** Rules of linking and unlinking. */
    private final FederatedLinkingPolicy federatedLinkingPolicy;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /**
     * Unlinks an identity; an identity of another account is never touched.
     *
     * @param userId   identifier of the signed-in user.
     * @param username name of the signed-in account, for the audit log.
     * @param id       identifier of the link.
     * @throws FederatedIdentityNotFoundException if the account has no such link.
     * @throws LastSignInMethodException          if the link is the last way the account can sign in.
     */
    public void execute(final UUID userId, final String username, final UUID id) {
        final var identity = federatedIdentityRepository.findByIdAndUser(id, userId)
                .orElseThrow(() -> new FederatedIdentityNotFoundException("The account has no identity " + id));
        final var remaining = new SignInMethods(
                !generatedPasswordRepository.isGenerated(userId),
                federatedIdentityRepository.countByUser(userId) - 1,
                passkeyRepository.existsForAccount(userId),
                certificateBindingRepository.findByUser(userId).size());
        if (!federatedLinkingPolicy.mayUnlink(remaining)) {
            throw new LastSignInMethodException("The identity is the last way to sign in to the account");
        }
        if (!federatedIdentityRepository.delete(id, userId)) {
            throw new FederatedIdentityNotFoundException("The account has no identity " + id);
        }
        recordSecurityEventUseCase.execute(SecurityEventType.IDENTITY_UNLINKED, userId, username,
                identity.provider().id());
    }
}
