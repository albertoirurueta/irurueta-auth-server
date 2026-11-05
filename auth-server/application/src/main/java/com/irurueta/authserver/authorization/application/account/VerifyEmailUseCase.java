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

import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.InvalidAccountTokenException;
import com.irurueta.authserver.authorization.domain.account.SignedTokenService;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that confirms an e-mail address from the signed token that was mailed to it, which also enables the
 * account.
 */
@Service
@RequiredArgsConstructor
public class VerifyEmailUseCase {

    /** Port that verifies the token. */
    private final SignedTokenService signedTokenService;

    /** Port that stores the accounts. */
    private final UserAccountRepository userAccountRepository;

    /**
     * Verifies the e-mail address the token was issued for.
     *
     * @param token the signed verification token.
     * @throws InvalidAccountTokenException if the token is not valid.
     */
    public void execute(final String token) {
        final var subject = signedTokenService.verify(token, AccountToken.PURPOSE_EMAIL_VERIFICATION)
                .orElseThrow(InvalidAccountTokenException::new);
        userAccountRepository.markEmailVerified(parseUserId(subject));
    }

    /**
     * Parses the subject of a verified token.
     *
     * @param subject the subject.
     * @return the user id.
     * @throws InvalidAccountTokenException if the subject is not a user id.
     */
    private static UUID parseUserId(final String subject) {
        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException e) {
            throw new InvalidAccountTokenException();
        }
    }
}
