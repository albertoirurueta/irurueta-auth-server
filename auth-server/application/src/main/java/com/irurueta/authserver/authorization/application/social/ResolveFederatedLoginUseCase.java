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

import com.irurueta.authserver.authorization.application.account.RegisterAccountUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.account.TokenGenerator;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedLinkingPolicy;
import com.irurueta.authserver.authorization.domain.social.FederatedLoginRefusedException;
import com.irurueta.authserver.authorization.domain.social.GeneratedPasswordRepository;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that resolves a sign-in with an external provider to a local account. The provider's stable subject, never
 * its e-mail address, finds the account. In order:
 * <ol>
 *     <li>an identity that is already linked signs in its account;</li>
 *     <li>otherwise the provider must vouch for the e-mail address: an unverified address never links and never
 *     provisions;</li>
 *     <li>an account that has that address and has verified it too is linked to the identity;</li>
 *     <li>an address that belongs to an account that never verified it is refused, so a pre-registered account cannot
 *     capture the victim's sign-in;</li>
 *     <li>otherwise a new, enabled account is provisioned, whose password is a random one nobody knows.</li>
 * </ol>
 */
@Service
@Transactional
@RequiredArgsConstructor
public class ResolveFederatedLoginUseCase {

    /** Longest username the {@code users} table accepts. */
    static final int MAX_USERNAME_LENGTH = 100;

    /** Port that stores the links. */
    private final FederatedIdentityRepository federatedIdentityRepository;

    /** Port that stores the accounts. */
    private final UserAccountRepository userAccountRepository;

    /** Port that remembers the accounts that only hold a generated password. */
    private final GeneratedPasswordRepository generatedPasswordRepository;

    /** Port that hashes the generated password. */
    private final PasswordHasher passwordHasher;

    /** Port that generates the unguessable secret the generated password is made of. */
    private final TokenGenerator tokenGenerator;

    /** Rules of linking and provisioning. */
    private final FederatedLinkingPolicy federatedLinkingPolicy;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Resolves a sign-in.
     *
     * @param provider      provider that authenticated the user.
     * @param subject       stable identifier the provider assigned to the user.
     * @param email         e-mail address the provider reported, or {@code null}.
     * @param emailVerified whether the provider says it verified the address.
     * @return the account the sign-in resolved to and how it was found.
     * @throws FederatedLoginRefusedException if the identity is not linked and the provider does not vouch for a usable
     *                                        e-mail address, or the address belongs to an unverified account.
     */
    public FederatedLogin execute(
            final IdentityProvider provider, final String subject, final String email, final boolean emailVerified) {
        final var now = clock.instant();
        final var existing = federatedIdentityRepository.findByProviderAndSubject(provider, subject);
        if (existing.isPresent()) {
            return signIn(existing.get(), email, now);
        }
        if (!federatedLinkingPolicy.mayProvision(email, emailVerified)) {
            throw new FederatedLoginRefusedException("The provider did not verify an e-mail address");
        }
        final var sameAddress = userAccountRepository.findByEmail(email);
        if (sameAddress.isPresent()) {
            final var account = sameAddress.get();
            if (!federatedLinkingPolicy.mayLinkByEmail(account, email, emailVerified)) {
                throw new FederatedLoginRefusedException("The e-mail address belongs to an unverified account");
            }
            return new FederatedLogin(account, link(account, provider, subject, email, now),
                    FederatedLoginOutcome.LINKED);
        }
        final var account = provision(provider, email);
        return new FederatedLogin(account, link(account, provider, subject, email, now),
                FederatedLoginOutcome.PROVISIONED);
    }

    /**
     * Signs in the account of an identity that is already linked, remembering the sign-in.
     *
     * @param identity the stored link.
     * @param email    e-mail address the provider reported now, or {@code null}.
     * @param now      current instant.
     * @return the resolution.
     */
    private FederatedLogin signIn(final FederatedIdentity identity, final String email, final Instant now) {
        final var account = userAccountRepository.findById(identity.userId())
                .orElseThrow(() -> new FederatedLoginRefusedException("The linked account no longer exists"));
        final var updated = federatedIdentityRepository.save(new FederatedIdentity(identity.id(), identity.userId(),
                identity.provider(), identity.subject(), email == null ? identity.email() : email,
                identity.linkedAt(), now));
        return new FederatedLogin(account, updated, FederatedLoginOutcome.EXISTING);
    }

    /**
     * Links an identity to an account and audits it.
     *
     * @param account  the account.
     * @param provider provider of the identity.
     * @param subject  subject of the identity.
     * @param email    e-mail address the provider reported.
     * @param now      current instant.
     * @return the stored link.
     */
    private FederatedIdentity link(final UserAccount account, final IdentityProvider provider, final String subject,
                                   final String email, final Instant now) {
        final var stored = federatedIdentityRepository.save(
                new FederatedIdentity(UUID.randomUUID(), account.id(), provider, subject, email, now, now));
        recordSecurityEventUseCase.execute(SecurityEventType.IDENTITY_LINKED, account.id(), account.username(),
                provider.id());
        return stored;
    }

    /**
     * Creates an enabled account from the provider's verified e-mail address. Its password is the hash of a random
     * secret that is discarded, and the account is marked as having no password of its own.
     *
     * @param provider provider that vouched for the address.
     * @param email    verified e-mail address.
     * @return the new account.
     */
    private UserAccount provision(final IdentityProvider provider, final String email) {
        final var id = UUID.randomUUID();
        final var username = userAccountRepository.existsByUsername(email) || email.length() > MAX_USERNAME_LENGTH
                ? provider.id() + "-" + id : email;
        final var account = new UserAccount(id, username, passwordHasher.encode(tokenGenerator.generate()), true,
                List.of(RegisterAccountUseCase.DEFAULT_AUTHORITY), email, true, UserAccount.DEFAULT_TENANT);
        userAccountRepository.save(account);
        generatedPasswordRepository.markGenerated(id);
        return account;
    }
}
