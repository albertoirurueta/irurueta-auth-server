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
import static org.mockito.Mockito.inOrder;
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
import com.irurueta.authserver.authorization.domain.password.PasswordPolicy;
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
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Transactional;

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

    /** Real password policy, spied so the use case is injected with it like with the bean. */
    @Spy
    private PasswordPolicy passwordPolicy = new PasswordPolicy();

    /** Use case under test. */
    @InjectMocks
    private ResetPasswordUseCase useCase;

    /**
     * Verifies that a valid token is consumed only after every check, then the password is replaced and the tokens
     * of the user are revoked.
     */
    @Test
    void execute_whenTokenIsValid_updatesPasswordAndRevokesTokens() {
        final var account = account();
        final var token = token(account.id());
        stubFind(Optional.of(token));
        when(userAccountRepository.findById(account.id())).thenReturn(Optional.of(account));
        when(accountTokenRepository.consume(HASH, AccountToken.PURPOSE_PASSWORD_RESET, NOW))
                .thenReturn(Optional.of(token));
        when(passwordHasher.encode(PASSWORD)).thenReturn(ENCODED);

        useCase.execute(TOKEN, PASSWORD);

        final var order = inOrder(compromisedPasswordCheck, accountTokenRepository, userAccountRepository,
                revokeUserAuthorizationsUseCase);
        order.verify(compromisedPasswordCheck).isCompromised(PASSWORD);
        order.verify(accountTokenRepository).consume(HASH, AccountToken.PURPOSE_PASSWORD_RESET, NOW);
        order.verify(userAccountRepository).updatePassword(account.id(), ENCODED);
        order.verify(revokeUserAuthorizationsUseCase).execute(USERNAME);
    }

    /**
     * Verifies that an unknown, expired or used token is rejected and nothing changes.
     */
    @Test
    void execute_whenTokenIsNotUsable_throwsInvalidAccountTokenException() {
        stubFind(Optional.empty());

        assertThrows(InvalidAccountTokenException.class, () -> useCase.execute(TOKEN, PASSWORD));

        verify(accountTokenRepository, never()).consume(any(), any(), any());
        verify(userAccountRepository, never()).updatePassword(any(), any());
        verifyNoInteractions(revokeUserAuthorizationsUseCase);
    }

    /**
     * Verifies that a token consumed concurrently by another reset, between the look-up and the consumption, is
     * rejected and nothing changes.
     */
    @Test
    void execute_whenTokenIsConsumedConcurrently_throwsInvalidAccountTokenException() {
        final var account = account();
        stubFind(Optional.of(token(account.id())));
        when(userAccountRepository.findById(account.id())).thenReturn(Optional.of(account));
        when(accountTokenRepository.consume(HASH, AccountToken.PURPOSE_PASSWORD_RESET, NOW))
                .thenReturn(Optional.empty());

        assertThrows(InvalidAccountTokenException.class, () -> useCase.execute(TOKEN, PASSWORD));

        verify(userAccountRepository, never()).updatePassword(any(), any());
        verifyNoInteractions(revokeUserAuthorizationsUseCase);
    }

    /**
     * Verifies that a token whose account no longer exists is rejected without being consumed.
     */
    @Test
    void execute_whenAccountIsGone_throwsInvalidAccountTokenException() {
        final var userId = UUID.randomUUID();
        stubFind(Optional.of(token(userId)));
        when(userAccountRepository.findById(userId)).thenReturn(Optional.empty());

        assertThrows(InvalidAccountTokenException.class, () -> useCase.execute(TOKEN, PASSWORD));

        verify(accountTokenRepository, never()).consume(any(), any(), any());
    }

    /**
     * Verifies that a password that breaks the policy is rejected without consuming the token.
     */
    @Test
    void execute_whenPasswordBreaksPolicy_throwsInvalidPasswordExceptionWithoutConsumingToken() {
        final var account = account();
        stubFind(Optional.of(token(account.id())));
        when(userAccountRepository.findById(account.id())).thenReturn(Optional.of(account));

        assertThrows(InvalidPasswordException.class, () -> useCase.execute(TOKEN, "short"));

        verify(accountTokenRepository, never()).consume(any(), any(), any());
    }

    /**
     * Verifies that a password containing the username is rejected without consuming the token, so the user can
     * retry with the same link.
     */
    @Test
    void execute_whenPasswordContainsUsername_throwsInvalidPasswordExceptionWithoutConsumingToken() {
        final var account = account();
        stubFind(Optional.of(token(account.id())));
        when(userAccountRepository.findById(account.id())).thenReturn(Optional.of(account));

        assertThrows(InvalidPasswordException.class, () -> useCase.execute(TOKEN, "my alice password"));

        verify(accountTokenRepository, never()).consume(any(), any(), any());
        verify(userAccountRepository, never()).updatePassword(any(), any());
    }

    /**
     * Verifies that a compromised password is rejected without consuming the token.
     */
    @Test
    void execute_whenPasswordIsCompromised_throwsCompromisedPasswordExceptionWithoutConsumingToken() {
        final var account = account();
        stubFind(Optional.of(token(account.id())));
        when(userAccountRepository.findById(account.id())).thenReturn(Optional.of(account));
        when(compromisedPasswordCheck.isCompromised(PASSWORD)).thenReturn(true);

        assertThrows(CompromisedPasswordException.class, () -> useCase.execute(TOKEN, PASSWORD));

        verify(accountTokenRepository, never()).consume(any(), any(), any());
    }


    /**
     * Verifies that the use case runs in one transaction: consuming the token, the new hash and the revocation of
     * the tokens are one unit.
     *
     * @throws NoSuchMethodException if the method is missing.
     */
    @Test
    void execute_whenInspected_isTransactional() throws NoSuchMethodException {
        final var method = ResetPasswordUseCase.class.getMethod("execute", String.class, String.class);

        assertNotNull(method.getAnnotation(Transactional.class));
    }

    /**
     * Stubs the look-up, without consumption, of the reset token.
     *
     * @param result what the repository returns.
     */
    private void stubFind(final Optional<AccountToken> result) {
        when(tokenGenerator.hash(TOKEN)).thenReturn(HASH);
        when(clock.instant()).thenReturn(NOW);
        when(accountTokenRepository.findUsable(HASH, AccountToken.PURPOSE_PASSWORD_RESET, NOW)).thenReturn(result);
    }

    /**
     * Creates the account the tests reset.
     *
     * @return the account.
     */
    private static UserAccount account() {
        return new UserAccount(UUID.randomUUID(), USERNAME, "{noop}x", true, List.of());
    }

    /**
     * Creates a usable reset token of an account.
     *
     * @param userId identifier of the account.
     * @return the token.
     */
    private static AccountToken token(final UUID userId) {
        return new AccountToken(UUID.randomUUID(), userId, AccountToken.PURPOSE_PASSWORD_RESET, HASH,
                NOW.plusSeconds(1), null);
    }
}
