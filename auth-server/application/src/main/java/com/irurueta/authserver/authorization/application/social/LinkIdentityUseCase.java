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
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityAlreadyLinkedException;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Clock;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that links an identity of an external provider to the account of a signed-in user. Unlike the sign-in, it
 * does not depend on the e-mail address: the user proved to own the account by being signed in, and the provider by
 * having just authenticated.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class LinkIdentityUseCase {

    /** Port that stores the links. */
    private final FederatedIdentityRepository federatedIdentityRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Links an identity to an account. Linking an identity the account already has changes nothing.
     *
     * @param userId   identifier of the signed-in user.
     * @param username name of the signed-in account, for the audit log.
     * @param provider provider that authenticated the user.
     * @param subject  stable identifier the provider assigned to the user.
     * @param email    e-mail address the provider reported, or {@code null}.
     * @return the link.
     * @throws FederatedIdentityAlreadyLinkedException if the identity belongs to another account.
     */
    public FederatedIdentity execute(final UUID userId, final String username, final IdentityProvider provider,
                                     final String subject, final String email) {
        final var existing = federatedIdentityRepository.findByProviderAndSubject(provider, subject);
        if (existing.isPresent()) {
            if (existing.get().userId().equals(userId)) {
                return existing.get();
            }
            throw new FederatedIdentityAlreadyLinkedException("The identity is linked to another account");
        }
        final var now = clock.instant();
        final var stored = federatedIdentityRepository.save(
                new FederatedIdentity(UUID.randomUUID(), userId, provider, subject, email, now, null));
        recordSecurityEventUseCase.execute(SecurityEventType.IDENTITY_LINKED, userId, username, provider.id());
        return stored;
    }
}
