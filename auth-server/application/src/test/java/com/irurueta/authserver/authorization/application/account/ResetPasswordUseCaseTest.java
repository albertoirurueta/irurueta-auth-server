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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.tokens.RevokeUserAuthorizationsUseCase;
import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.AccountTokenRepository;
import com.irurueta.authserver.authorization.domain.account.InvalidAccountTokenException;
import com.irurueta.authserver.authorization.domain.account.TokenGenerator;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ResetPasswordUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ResetPasswordUseCaseTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Token used by the tests. */
    private static final String TOKEN = "opaque";

    /** Hash of the token used by the tests. */
    private static final String HASH = "hashed";

    /** Acceptable clear-text password used by the tests; not a real credential. */
    private static final String PASSWORD = "brand new password";

    /** Encoded new password. */
    private static final String ENCODED = "{argon2}new";

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Port that stores the accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Port that stores the reset tokens. */
    @Mock
    private AccountTokenRepository accountTokenRepository;

    /** Port that creates and hashes tokens. */
    @Mock
    private TokenGenerator tokenGenerator;

    /** Port that hashes passwords. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Port that checks passwords against leaked ones. */
    @Mock
    private CompromisedPasswordCheck compromisedPasswordCheck;

    /** Use case that revokes the tokens of the user. */
    @Mock
    private RevokeUserAuthorizationsUseCase revokeUserAuthorizationsUseCase;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private ResetPasswordUseCase useCase;

    /**
     * Verifies that a valid token replaces the password and revokes the tokens of the user.
     */
    @Test
    void execute_whenTokenIsValid_updatesPasswordAndRevokesTokens() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, "{noop}x", true, List.of());
        stubConsume(Optional.of(new AccountToken(UUID.randomUUID(), account.id(),
                AccountToken.PURPOSE_PASSWORD_RESET, HASH, NOW, NOW)));
        when(userAccountRepository.findById(account.id())).thenReturn(Optional.of(account));
        when(passwordHasher.encode(PASSWORD)).thenReturn(ENCODED);

        useCase.execute(TOKEN, PASSWORD);

        verify(userAccountRepository).updatePassword(account.id(), ENCODED);
        verify(revokeUserAuthorizationsUseCase).execute(USERNAME);
    }

    /**
     * Verifies that an unknown, expired or used token is rejected and nothing changes.
     */
    @Test
    void execute_whenTokenCannotBeConsumed_throwsInvalidAccountTokenException() {
        stubConsume(Optional.empty());

        assertThrows(InvalidAccountTokenException.class, () -> useCase.execute(TOKEN, PASSWORD));

        verify(userAccountRepository, never()).updatePassword(any(), any());
        verifyNoInteractions(revokeUserAuthorizationsUseCase);
    }

    /**
     * Verifies that a token whose account no longer exists is rejected.
     */
    @Test
    void execute_whenAccountIsGone_throwsInvalidAccountTokenException() {
        final var userId = UUID.randomUUID();
        stubConsume(Optional.of(new AccountToken(UUID.randomUUID(), userId,
                AccountToken.PURPOSE_PASSWORD_RESET, HASH, NOW, NOW)));
        when(userAccountRepository.findById(userId)).thenReturn(Optional.empty());

        assertThrows(InvalidAccountTokenException.class, () -> useCase.execute(TOKEN, PASSWORD));
    }

    /**
     * Verifies that a password that breaks the policy is rejected without consuming the token.
     */
    @Test
    void execute_whenPasswordBreaksPolicy_throwsInvalidPasswordExceptionWithoutConsumingToken() {
        assertThrows(InvalidPasswordException.class, () -> useCase.execute(TOKEN, "short"));

        verifyNoInteractions(accountTokenRepository);
    }

    /**
     * Verifies that a password containing the username is rejected once the account is known.
     */
    @Test
    void execute_whenPasswordContainsUsername_throwsInvalidPasswordException() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, "{noop}x", true, List.of());
        stubConsume(Optional.of(new AccountToken(UUID.randomUUID(), account.id(),
                AccountToken.PURPOSE_PASSWORD_RESET, HASH, NOW, NOW)));
        when(userAccountRepository.findById(account.id())).thenReturn(Optional.of(account));

        assertThrows(InvalidPasswordException.class, () -> useCase.execute(TOKEN, "my alice password"));

        verify(userAccountRepository, never()).updatePassword(any(), any());
    }

    /**
     * Verifies that a compromised password is rejected without consuming the token.
     */
    @Test
    void execute_whenPasswordIsCompromised_throwsCompromisedPasswordException() {
        when(compromisedPasswordCheck.isCompromised(PASSWORD)).thenReturn(true);

        assertThrows(CompromisedPasswordException.class, () -> useCase.execute(TOKEN, PASSWORD));

        verifyNoInteractions(accountTokenRepository);
    }

    /**
     * Stubs the single-use consumption of the reset token.
     *
     * @param result what the repository returns.
     */
    private void stubConsume(final Optional<AccountToken> result) {
        when(tokenGenerator.hash(TOKEN)).thenReturn(HASH);
        when(clock.instant()).thenReturn(NOW);
        when(accountTokenRepository.consume(HASH, AccountToken.PURPOSE_PASSWORD_RESET, NOW)).thenReturn(result);
    }
}
