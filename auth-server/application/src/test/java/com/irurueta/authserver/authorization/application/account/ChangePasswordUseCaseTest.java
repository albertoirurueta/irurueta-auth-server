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
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.tokens.RevokeUserAuthorizationsUseCase;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordException;
import com.irurueta.authserver.authorization.domain.password.InvalidCredentialsException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.PasswordPolicy;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Transactional;

/**
 * Unit tests of {@link ChangePasswordUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ChangePasswordUseCaseTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Current clear-text password used by the tests; not a real credential. */
    private static final String CURRENT = "current password";

    /** New clear-text password used by the tests; not a real credential. */
    private static final String NEW_PASSWORD = "brand new password";

    /** Encoded current password. */
    private static final String CURRENT_ENCODED = "{argon2}current";

    /** Encoded new password. */
    private static final String NEW_ENCODED = "{argon2}new";

    /** Port that stores the accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Port that hashes passwords. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Port that checks passwords against leaked ones. */
    @Mock
    private CompromisedPasswordCheck compromisedPasswordCheck;

    /** Use case that revokes the tokens of the user. */
    @Mock
    private RevokeUserAuthorizationsUseCase revokeUserAuthorizationsUseCase;

    /** Real password policy, spied so the use case is injected with it like with the bean. */
    @Spy
    private PasswordPolicy passwordPolicy = new PasswordPolicy();

    /** Use case under test. */
    @InjectMocks
    private ChangePasswordUseCase useCase;

    /**
     * Verifies that the password is replaced and the tokens of the user are revoked.
     */
    @Test
    void execute_whenCurrentPasswordMatches_updatesPasswordAndRevokesTokens() {
        final var account = account();
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));
        when(passwordHasher.matches(CURRENT, CURRENT_ENCODED)).thenReturn(true);
        when(passwordHasher.encode(NEW_PASSWORD)).thenReturn(NEW_ENCODED);

        useCase.execute(USERNAME, CURRENT, NEW_PASSWORD);

        verify(userAccountRepository).updatePassword(account.id(), NEW_ENCODED);
        verify(revokeUserAuthorizationsUseCase).execute(USERNAME);
    }

    /**
     * Verifies that an unknown user is rejected like a wrong password.
     */
    @Test
    void execute_whenUserIsUnknown_throwsInvalidCredentialsException() {
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class, () -> useCase.execute(USERNAME, CURRENT, NEW_PASSWORD));

        verifyNoInteractions(revokeUserAuthorizationsUseCase);
    }

    /**
     * Verifies that a wrong current password is rejected.
     */
    @Test
    void execute_whenCurrentPasswordIsWrong_throwsInvalidCredentialsException() {
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account()));
        when(passwordHasher.matches(CURRENT, CURRENT_ENCODED)).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> useCase.execute(USERNAME, CURRENT, NEW_PASSWORD));

        verify(userAccountRepository, never()).updatePassword(any(),
                any());
    }

    /**
     * Verifies that a new password that breaks the policy is rejected.
     */
    @Test
    void execute_whenNewPasswordBreaksPolicy_throwsInvalidPasswordException() {
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account()));
        when(passwordHasher.matches(CURRENT, CURRENT_ENCODED)).thenReturn(true);

        assertThrows(InvalidPasswordException.class, () -> useCase.execute(USERNAME, CURRENT, "short"));

        verifyNoInteractions(revokeUserAuthorizationsUseCase);
    }

    /**
     * Verifies that a compromised new password is rejected.
     */
    @Test
    void execute_whenNewPasswordIsCompromised_throwsCompromisedPasswordException() {
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account()));
        when(passwordHasher.matches(CURRENT, CURRENT_ENCODED)).thenReturn(true);
        when(compromisedPasswordCheck.isCompromised(NEW_PASSWORD)).thenReturn(true);

        assertThrows(CompromisedPasswordException.class, () -> useCase.execute(USERNAME, CURRENT, NEW_PASSWORD));

        verifyNoInteractions(revokeUserAuthorizationsUseCase);
    }


    /**
     * Verifies that the use case runs in one transaction: the new hash and the revocation of the tokens are one unit.
     *
     * @throws NoSuchMethodException if the method is missing.
     */
    @Test
    void execute_whenInspected_isTransactional() throws NoSuchMethodException {
        final var method = ChangePasswordUseCase.class.getMethod("execute", String.class, String.class, String.class);

        assertNotNull(method.getAnnotation(Transactional.class));
    }

    /**
     * Creates the account of the user.
     *
     * @return the account.
     */
    private static UserAccount account() {
        return new UserAccount(UUID.randomUUID(), USERNAME, CURRENT_ENCODED, true, List.of());
    }
}
