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

package com.irurueta.authserver.authorization.application.account;

import com.irurueta.authserver.authorization.domain.account.AccountMailer;
import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.SignedTokenService;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.PasswordPolicy;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that registers an account. The account starts disabled and unverified; a signed verification token is
 * e-mailed to the address. The answer is always the same and the password is always hashed, so neither the answer
 * nor its timing reveals whether the address or the username is taken. What the address receives differs only where
 * its owner learns nothing new:
 * <ul>
 *     <li>a registered address gets a neutral "already registered" message: its owner already knows it has an
 *     account;</li>
 *     <li>a new address with a taken username gets the usual verification message, whose token names no account, so
 *     following it fails exactly like an expired link. The username is never confirmed to whoever controls the
 *     address, so the endpoint cannot be used to find out which usernames exist.</li>
 * </ul>
 * The account is saved and the message sent in one transaction: if the mail cannot be sent, nothing is registered.
 */
@Service
@RequiredArgsConstructor
public class RegisterAccountUseCase {

    /** Authority granted to registered accounts. */
    public static final String DEFAULT_AUTHORITY = "ROLE_USER";

    /** How long the e-mailed verification token stays valid. */
    public static final Duration VERIFICATION_TTL = Duration.ofHours(24);

    /** Port that stores the accounts. */
    private final UserAccountRepository userAccountRepository;

    /** Port that hashes passwords. */
    private final PasswordHasher passwordHasher;

    /** Port that checks passwords against leaked ones. */
    private final CompromisedPasswordCheck compromisedPasswordCheck;

    /** Port that issues the verification token. */
    private final SignedTokenService signedTokenService;

    /** Port that sends the e-mails. */
    private final AccountMailer accountMailer;

    /** Rules a new password must follow. */
    private final PasswordPolicy passwordPolicy;

    // tag::account-register[]
    /**
     * Registers an account.
     *
     * @param username name the user will sign in with.
     * @param email    e-mail address of the user.
     * @param password the chosen clear-text password.
     * @throws InvalidPasswordException     if the password breaks the policy.
     * @throws CompromisedPasswordException if the password is known to be compromised.
     */
    @Transactional
    public void execute(final String username, final String email, final String password) {
        final var violations = passwordPolicy.violations(username, password);
        if (!violations.isEmpty()) {
            throw new InvalidPasswordException(violations);
        }
        if (compromisedPasswordCheck.isCompromised(password)) {
            throw new CompromisedPasswordException("The chosen password is known to be compromised");
        }
        // hashed in every case, so that a taken address or username costs the same as a new one
        final var encodedPassword = passwordHasher.encode(password);
        if (userAccountRepository.findByEmail(email).isPresent()) {
            accountMailer.sendAlreadyRegistered(email);
            return;
        }
        final var id = UUID.randomUUID();
        // issued in every remaining case; with a taken username it names no account and verifies nothing
        final var token = signedTokenService.issue(id.toString(), AccountToken.PURPOSE_EMAIL_VERIFICATION,
                VERIFICATION_TTL);
        if (!userAccountRepository.existsByUsername(username)) {
            userAccountRepository.save(new UserAccount(id, username, encodedPassword, false,
                    List.of(DEFAULT_AUTHORITY), email, false, UserAccount.DEFAULT_TENANT));
        }
        accountMailer.sendEmailVerification(email, token);
    }
    // end::account-register[]
}
