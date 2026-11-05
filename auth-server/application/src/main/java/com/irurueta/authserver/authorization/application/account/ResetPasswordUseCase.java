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

import com.irurueta.authserver.authorization.application.tokens.RevokeUserAuthorizationsUseCase;
import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.AccountTokenRepository;
import com.irurueta.authserver.authorization.domain.account.InvalidAccountTokenException;
import com.irurueta.authserver.authorization.domain.account.TokenGenerator;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.PasswordPolicy;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that chooses a new password with the single-use token received by e-mail. Every check (token, account,
 * password policy including the username rule, compromised-password check) runs before the token is consumed, so a
 * rejected password never burns the token; consuming it, storing the new hash and revoking every token of the user
 * then happen in one transaction.
 */
@Service
@RequiredArgsConstructor
public class ResetPasswordUseCase {

    /** Port that stores the accounts. */
    private final UserAccountRepository userAccountRepository;

    /** Port that stores the reset tokens. */
    private final AccountTokenRepository accountTokenRepository;

    /** Port that creates and hashes tokens. */
    private final TokenGenerator tokenGenerator;

    /** Port that hashes passwords. */
    private final PasswordHasher passwordHasher;

    /** Port that checks passwords against leaked ones. */
    private final CompromisedPasswordCheck compromisedPasswordCheck;

    /** Use case that revokes the tokens of the user. */
    private final RevokeUserAuthorizationsUseCase revokeUserAuthorizationsUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /** Rules a new password must follow. */
    private final PasswordPolicy passwordPolicy;

    // tag::account-reset-password[]
    /**
     * Resets the password of the user the token was issued to. The token is looked up without being consumed, every
     * check runs, and only then is the token consumed; the consumption is atomic, so of two concurrent resets with
     * the same token only one succeeds.
     *
     * @param token       the reset token received by e-mail.
     * @param newPassword the clear-text new password.
     * @throws InvalidPasswordException     if the password breaks the policy.
     * @throws CompromisedPasswordException if the password is known to be compromised.
     * @throws InvalidAccountTokenException if the token is unknown, expired, used or its account is gone.
     */
    @Transactional
    public void execute(final String token, final String newPassword) {
        final var hashedToken = tokenGenerator.hash(token);
        final var now = clock.instant();
        final var stored = accountTokenRepository
                .findUsable(hashedToken, AccountToken.PURPOSE_PASSWORD_RESET, now)
                .orElseThrow(InvalidAccountTokenException::new);
        final var account = userAccountRepository.findById(stored.userId())
                .orElseThrow(InvalidAccountTokenException::new);
        requirePolicy(account.username(), newPassword);
        requireNotCompromised(newPassword);
        accountTokenRepository.consume(hashedToken, AccountToken.PURPOSE_PASSWORD_RESET, now)
                .orElseThrow(InvalidAccountTokenException::new);
        userAccountRepository.updatePassword(account.id(), passwordHasher.encode(newPassword));
        revokeUserAuthorizationsUseCase.execute(account.username());
    }
    // end::account-reset-password[]

    /**
     * Rejects a password that breaks the policy.
     *
     * @param username name of the account the password is for.
     * @param password the clear-text password.
     */
    private void requirePolicy(final String username, final String password) {
        final var violations = passwordPolicy.violations(username, password);
        if (!violations.isEmpty()) {
            throw new InvalidPasswordException(violations);
        }
    }

    /**
     * Rejects a compromised password.
     *
     * @param password the clear-text password.
     */
    private void requireNotCompromised(final String password) {
        if (compromisedPasswordCheck.isCompromised(password)) {
            throw new CompromisedPasswordException("The chosen password is known to be compromised");
        }
    }
}
