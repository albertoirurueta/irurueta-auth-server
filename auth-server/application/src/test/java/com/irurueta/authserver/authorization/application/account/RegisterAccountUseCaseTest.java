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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.account.AccountMailer;
import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.SignedTokenService;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RegisterAccountUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RegisterAccountUseCaseTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Acceptable clear-text password used by the tests; not a real credential. */
    private static final String PASSWORD = "correct horse battery";

    /** Encoded password returned by the mocked hasher. */
    private static final String ENCODED = "{argon2}encoded";

    /** Port that stores the accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Port that hashes passwords. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Port that checks passwords against leaked ones. */
    @Mock
    private CompromisedPasswordCheck compromisedPasswordCheck;

    /** Port that issues the verification token. */
    @Mock
    private SignedTokenService signedTokenService;

    /** Port that sends the e-mails. */
    @Mock
    private AccountMailer accountMailer;

    /** Use case under test. */
    @InjectMocks
    private RegisterAccountUseCase useCase;

    /**
     * Verifies that a new account is stored disabled and unverified, and a verification token is mailed.
     */
    @Test
    void execute_whenAddressIsNew_storesAccountAndMailsToken() {
        when(passwordHasher.encode(PASSWORD)).thenReturn(ENCODED);
        when(userAccountRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(signedTokenService.issue(any(), any(), any())).thenReturn("signed");

        useCase.execute(USERNAME, EMAIL, PASSWORD);

        final var captor = ArgumentCaptor.<UserAccount>captor();
        verify(userAccountRepository).save(captor.capture());
        final var account = captor.getValue();
        assertEquals(USERNAME, account.username());
        assertEquals(ENCODED, account.encodedPassword());
        assertFalse(account.enabled());
        assertFalse(account.emailVerified());
        assertEquals(EMAIL, account.email());
        assertTrue(account.authorities().contains(RegisterAccountUseCase.DEFAULT_AUTHORITY));
        verify(signedTokenService).issue(account.id().toString(), AccountToken.PURPOSE_EMAIL_VERIFICATION,
                RegisterAccountUseCase.VERIFICATION_TTL);
        verify(accountMailer).sendEmailVerification(EMAIL, "signed");
    }

    /**
     * Verifies that an existing address gets a neutral message, after the same hashing work, and nothing is stored.
     */
    @Test
    void execute_whenAddressIsRegistered_mailsNeutralMessageAfterHashing() {
        when(passwordHasher.encode(PASSWORD)).thenReturn(ENCODED);
        when(userAccountRepository.existsByUsername(USERNAME)).thenReturn(false);
        when(userAccountRepository.findByEmail(EMAIL)).thenReturn(Optional.of(
                new UserAccount(UUID.randomUUID(), "bob", ENCODED, true, List.of())));

        useCase.execute(USERNAME, EMAIL, PASSWORD);

        verify(passwordHasher).encode(PASSWORD);
        verify(accountMailer).sendAlreadyRegistered(EMAIL);
        verify(userAccountRepository, never()).save(any());
        verifyNoInteractions(signedTokenService);
    }

    /**
     * Verifies that an existing username is treated like an existing address.
     */
    @Test
    void execute_whenUsernameIsTaken_mailsNeutralMessage() {
        when(passwordHasher.encode(PASSWORD)).thenReturn(ENCODED);
        when(userAccountRepository.existsByUsername(USERNAME)).thenReturn(true);

        useCase.execute(USERNAME, EMAIL, PASSWORD);

        verify(accountMailer).sendAlreadyRegistered(EMAIL);
        verify(userAccountRepository, never()).save(any());
    }

    /**
     * Verifies that a password that breaks the policy is rejected before anything else happens.
     */
    @Test
    void execute_whenPasswordBreaksPolicy_throwsInvalidPasswordException() {
        assertThrows(InvalidPasswordException.class, () -> useCase.execute(USERNAME, EMAIL, "short"));

        verifyNoInteractions(passwordHasher, userAccountRepository, accountMailer);
    }

    /**
     * Verifies that a compromised password is rejected.
     */
    @Test
    void execute_whenPasswordIsCompromised_throwsCompromisedPasswordException() {
        when(compromisedPasswordCheck.isCompromised(PASSWORD)).thenReturn(true);

        assertThrows(CompromisedPasswordException.class, () -> useCase.execute(USERNAME, EMAIL, PASSWORD));

        verifyNoInteractions(passwordHasher, userAccountRepository, accountMailer);
    }
}
