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

package com.irurueta.authserver.authorization.application.passkeys;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link HasConfirmedPasskeyUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class HasConfirmedPasskeyUseCaseTest {

    /** User handle of the account. */
    private static final String HANDLE = "handle";

    /** Port that reads the passkeys. */
    @Mock
    private PasskeyRepository passkeyRepository;

    /** Port that resolves the account of a user identifier. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Use case under test. */
    @InjectMocks
    private HasConfirmedPasskeyUseCase useCase;

    /**
     * Verifies that a user with a passkey is enrolled, through both entry points.
     */
    @Test
    void execute_whenUserHasAPasskey_returnsTrue() {
        final var userId = UUID.randomUUID();
        stubAccount(userId);
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.countByUserId(HANDLE)).thenReturn(1L);

        assertTrue(useCase.execute(userId));
        assertTrue(useCase.hasConfirmed(userId));
    }

    /**
     * Verifies that a user whose passkeys were all deleted is not enrolled.
     */
    @Test
    void execute_whenUserHasNoPasskey_returnsFalse() {
        final var userId = UUID.randomUUID();
        stubAccount(userId);
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.countByUserId(HANDLE)).thenReturn(0L);

        assertFalse(useCase.execute(userId));
    }

    /**
     * Verifies that a user that never registered a passkey is not enrolled.
     */
    @Test
    void hasConfirmed_whenUserHasNoEntity_returnsFalse() {
        final var userId = UUID.randomUUID();
        stubAccount(userId);
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.empty());

        assertFalse(useCase.hasConfirmed(userId));
    }

    /**
     * Verifies that an unknown user is not enrolled and no passkey is looked up.
     */
    @Test
    void hasConfirmed_whenAccountIsUnknown_returnsFalse() {
        final var userId = UUID.randomUUID();
        when(userAccountRepository.findById(userId)).thenReturn(Optional.empty());

        assertFalse(useCase.hasConfirmed(userId));

        verifyNoInteractions(passkeyRepository);
    }

    /**
     * Makes the account repository resolve the user to the account {@code alice}.
     *
     * @param userId identifier of the user.
     */
    private void stubAccount(final UUID userId) {
        when(userAccountRepository.findById(userId)).thenReturn(Optional.of(
                new UserAccount(userId, "alice", "{noop}x", true, List.of(), null, false,
                        UserAccount.DEFAULT_TENANT)));
    }
}
