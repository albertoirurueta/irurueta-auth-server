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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.account.AccountMailer;
import com.irurueta.authserver.authorization.domain.account.AccountToken;
import com.irurueta.authserver.authorization.domain.account.AccountTokenRepository;
import com.irurueta.authserver.authorization.domain.account.TokenGenerator;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Transactional;

/**
 * Unit tests of {@link RequestPasswordResetUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RequestPasswordResetUseCaseTest {

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Token used by the tests. */
    private static final String TOKEN = "opaque";

    /** Hash of the token used by the tests. */
    private static final String HASH = "hashed";

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

    /** Port that sends the e-mails. */
    @Mock
    private AccountMailer accountMailer;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private RequestPasswordResetUseCase useCase;

    /**
     * Verifies that the hash of a new token is stored and the token itself is mailed.
     */
    @Test
    void execute_whenAddressIsRegistered_storesHashedTokenAndMailsToken() {
        final var account = new UserAccount(UUID.randomUUID(), "alice", "{noop}x", true, List.of());
        when(tokenGenerator.generate()).thenReturn(TOKEN);
        when(tokenGenerator.hash(TOKEN)).thenReturn(HASH);
        when(userAccountRepository.findByEmail(EMAIL)).thenReturn(Optional.of(account));
        when(clock.instant()).thenReturn(NOW);

        useCase.execute(EMAIL);

        final var captor = ArgumentCaptor.<AccountToken>captor();
        verify(accountTokenRepository).store(captor.capture());
        final var stored = captor.getValue();
        assertEquals(account.id(), stored.userId());
        assertEquals(AccountToken.PURPOSE_PASSWORD_RESET, stored.purpose());
        assertEquals(HASH, stored.hashedToken());
        assertEquals(NOW.plus(RequestPasswordResetUseCase.RESET_TTL), stored.expiresAt());
        verify(accountMailer).sendPasswordReset(EMAIL, TOKEN);
    }

    /**
     * Verifies that an unknown address does the same token work, stores nothing and is never mailed, so the
     * endpoint cannot be used to send mail to arbitrary addresses.
     */
    @Test
    void execute_whenAddressIsUnknown_mailsNothingAfterSameWork() {
        when(tokenGenerator.generate()).thenReturn(TOKEN);
        when(tokenGenerator.hash(TOKEN)).thenReturn(HASH);
        when(userAccountRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        useCase.execute(EMAIL);

        verify(tokenGenerator).hash(TOKEN);
        verifyNoInteractions(accountTokenRepository, accountMailer);
    }

    /**
     * Verifies that the use case runs in one transaction: the stored token and its e-mail are one unit, so a mail
     * failure leaves no usable token.
     *
     * @throws NoSuchMethodException if the method is missing.
     */
    @Test
    void execute_whenInspected_isTransactional() throws NoSuchMethodException {
        final var method = RequestPasswordResetUseCase.class.getMethod("execute", String.class);

        assertNotNull(method.getAnnotation(Transactional.class));
    }
}
