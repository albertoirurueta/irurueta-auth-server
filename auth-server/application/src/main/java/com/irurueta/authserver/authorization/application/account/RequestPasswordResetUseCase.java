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
import com.irurueta.authserver.authorization.domain.account.AccountTokenRepository;
import com.irurueta.authserver.authorization.domain.account.TokenGenerator;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that starts a password reset. It always succeeds from the caller's point of view: an unknown address is
 * never mailed (so the endpoint cannot be used to send mail to arbitrary addresses) and costs the same token work (a
 * token is generated and hashed either way), so the response never reveals whether an address is registered. The
 * token is stored and mailed in one transaction: if the mail cannot be sent, no usable token is left behind.
 */
@Service
@RequiredArgsConstructor
public class RequestPasswordResetUseCase {

    /** How long a reset token stays valid. */
    public static final Duration RESET_TTL = Duration.ofMinutes(30);

    /** Port that stores the accounts. */
    private final UserAccountRepository userAccountRepository;

    /** Port that stores the reset tokens. */
    private final AccountTokenRepository accountTokenRepository;

    /** Port that creates and hashes tokens. */
    private final TokenGenerator tokenGenerator;

    /** Port that sends the e-mails. */
    private final AccountMailer accountMailer;

    /** Source of the current time. */
    private final Clock clock;

    // tag::account-reset[]
    /**
     * Requests a password reset.
     *
     * @param email e-mail address of the user.
     */
    @Transactional
    public void execute(final String email) {
        final var token = tokenGenerator.generate();
        final var hashedToken = tokenGenerator.hash(token);
        // an unknown address gets nothing: the token above was generated and hashed all the same
        userAccountRepository.findByEmail(email)
                .ifPresent(account -> sendReset(account, email, token, hashedToken));
    }

    /**
     * Stores the reset token and mails it.
     *
     * @param account     the account to reset.
     * @param email       address to send the message to.
     * @param token       the reset token.
     * @param hashedToken hash of the reset token.
     */
    private void sendReset(final UserAccount account, final String email, final String token,
                           final String hashedToken) {
        accountTokenRepository.store(new AccountToken(UUID.randomUUID(), account.id(),
                AccountToken.PURPOSE_PASSWORD_RESET, hashedToken, clock.instant().plus(RESET_TTL), null));
        accountMailer.sendPasswordReset(email, token);
    }
    // end::account-reset[]
}
