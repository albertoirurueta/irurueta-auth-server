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
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordException;
import com.irurueta.authserver.authorization.domain.password.InvalidCredentialsException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.PasswordPolicy;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that lets a signed-in user choose a new password. Every token of the user is revoked afterwards.
 */
@Service
@RequiredArgsConstructor
public class ChangePasswordUseCase {

    /** Port that stores the accounts. */
    private final UserAccountRepository userAccountRepository;

    /** Port that hashes passwords. */
    private final PasswordHasher passwordHasher;

    /** Port that checks passwords against leaked ones. */
    private final CompromisedPasswordCheck compromisedPasswordCheck;

    /** Use case that revokes the tokens of the user. */
    private final RevokeUserAuthorizationsUseCase revokeUserAuthorizationsUseCase;

    /** Rules a new password must follow. */
    private final PasswordPolicy passwordPolicy = new PasswordPolicy();

    /**
     * Changes the password of a user.
     *
     * @param username        name of the user.
     * @param currentPassword the clear-text current password.
     * @param newPassword     the clear-text new password.
     * @throws InvalidCredentialsException  if the user is unknown or the current password is wrong.
     * @throws InvalidPasswordException     if the new password breaks the policy.
     * @throws CompromisedPasswordException if the new password is known to be compromised.
     */
    public void execute(final String username, final String currentPassword, final String newPassword) {
        final var account = userAccountRepository.findByUsername(username)
                .filter(found -> passwordHasher.matches(currentPassword, found.encodedPassword()))
                .orElseThrow(() -> new InvalidCredentialsException("The username or password is wrong"));
        final var violations = passwordPolicy.violations(username, newPassword);
        if (!violations.isEmpty()) {
            throw new InvalidPasswordException(violations);
        }
        if (compromisedPasswordCheck.isCompromised(newPassword)) {
            throw new CompromisedPasswordException("The chosen password is known to be compromised");
        }
        userAccountRepository.updatePassword(account.id(), passwordHasher.encode(newPassword));
        revokeUserAuthorizationsUseCase.execute(account.username());
    }
}
