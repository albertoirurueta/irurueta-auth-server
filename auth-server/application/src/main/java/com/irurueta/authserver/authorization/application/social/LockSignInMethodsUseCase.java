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

import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.GeneratedPasswordRepository;
import com.irurueta.authserver.authorization.domain.social.SignInMethods;
import com.irurueta.authserver.authorization.domain.social.SignInMethodsLock;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

// tag::social-lock-sign-in-methods[]
/**
 * Use case that locks the sign-in methods of an account for the rest of the caller's transaction and counts them: a
 * password its owner knows (not a generated one), the linked identities, a passkey and the bound certificates. Every
 * use case that removes a sign-in method starts with it, so two concurrent removals of the same account are serialized
 * and the second one counts what the first left. It only runs inside the caller's transaction, which holds the lock.
 */
@Service
@Transactional(propagation = Propagation.MANDATORY)
@RequiredArgsConstructor
public class LockSignInMethodsUseCase {

    /** Port that serializes the removals of an account. */
    private final SignInMethodsLock signInMethodsLock;

    /** Port that stores the links. */
    private final FederatedIdentityRepository federatedIdentityRepository;

    /** Port that remembers the accounts that only hold a generated password. */
    private final GeneratedPasswordRepository generatedPasswordRepository;

    /** Port that reads the passkeys. */
    private final PasskeyRepository passkeyRepository;

    /** Port that reads the bound certificates. */
    private final CertificateBindingRepository certificateBindingRepository;

    /**
     * Locks the sign-in methods of an account and counts them.
     *
     * @param userId identifier of the account.
     * @return the ways the account can sign in now, counted once the lock is held.
     */
    public SignInMethods execute(final UUID userId) {
        signInMethodsLock.lock(userId);
        return new SignInMethods(
                !generatedPasswordRepository.isGenerated(userId),
                federatedIdentityRepository.countByUser(userId),
                passkeyRepository.existsForAccount(userId),
                certificateBindingRepository.findByUser(userId).size());
    }
}
// end::social-lock-sign-in-methods[]
