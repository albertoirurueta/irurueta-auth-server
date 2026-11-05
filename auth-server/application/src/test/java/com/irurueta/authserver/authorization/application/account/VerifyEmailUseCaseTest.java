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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.InvalidAccountTokenException;
import com.irurueta.authserver.authorization.domain.account.SignedTokenService;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Transactional;

/**
 * Unit tests of {@link VerifyEmailUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class VerifyEmailUseCaseTest {

    /** Token used by the tests. */
    private static final String TOKEN = "signed";

    /** Port that verifies the token. */
    @Mock
    private SignedTokenService signedTokenService;

    /** Port that stores the accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Use case under test. */
    @InjectMocks
    private VerifyEmailUseCase useCase;

    /**
     * Verifies that a valid token verifies the address of its subject.
     */
    @Test
    void execute_whenTokenIsValid_marksEmailVerified() {
        final var id = UUID.randomUUID();
        when(signedTokenService.verify(TOKEN, AccountToken.PURPOSE_EMAIL_VERIFICATION))
                .thenReturn(Optional.of(id.toString()));
        when(userAccountRepository.markEmailVerified(id)).thenReturn(true);

        useCase.execute(TOKEN);

        verify(userAccountRepository).markEmailVerified(id);
    }

    /**
     * Verifies that a replayed token (still unexpired, but its address is already verified) is rejected as an
     * invalid token, so it can never re-enable an account disabled in between.
     */
    @Test
    void execute_whenAddressIsAlreadyVerified_throwsInvalidAccountTokenException() {
        final var id = UUID.randomUUID();
        when(signedTokenService.verify(TOKEN, AccountToken.PURPOSE_EMAIL_VERIFICATION))
                .thenReturn(Optional.of(id.toString()));
        when(userAccountRepository.markEmailVerified(id)).thenReturn(false);

        assertThrows(InvalidAccountTokenException.class, () -> useCase.execute(TOKEN));
    }

    /**
     * Verifies that an invalid token is rejected.
     */
    @Test
    void execute_whenTokenIsInvalid_throwsInvalidAccountTokenException() {
        when(signedTokenService.verify(TOKEN, AccountToken.PURPOSE_EMAIL_VERIFICATION))
                .thenReturn(Optional.empty());

        assertThrows(InvalidAccountTokenException.class, () -> useCase.execute(TOKEN));

        verify(userAccountRepository, never()).markEmailVerified(any());
    }

    /**
     * Verifies that a token whose subject is not a user id is rejected.
     */
    @Test
    void execute_whenSubjectIsNotAUserId_throwsInvalidAccountTokenException() {
        when(signedTokenService.verify(TOKEN, AccountToken.PURPOSE_EMAIL_VERIFICATION))
                .thenReturn(Optional.of("not-a-uuid"));

        assertThrows(InvalidAccountTokenException.class, () -> useCase.execute(TOKEN));
    }

    /**
     * Verifies that the use case runs in one transaction: the verification is one unit.
     *
     * @throws NoSuchMethodException if the method is missing.
     */
    @Test
    void execute_whenInspected_isTransactional() throws NoSuchMethodException {
        final var method = VerifyEmailUseCase.class.getMethod("execute", String.class);

        assertNotNull(method.getAnnotation(Transactional.class));
    }
}
