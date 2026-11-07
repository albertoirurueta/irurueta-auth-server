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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link DeletePasskeyUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class DeletePasskeyUseCaseTest {

    /** User handle of the account. */
    private static final String HANDLE = "handle";

    /** Credential identifier. */
    private static final String ID = "cred";

    /** Port that stores the passkeys. */
    @Mock
    private PasskeyRepository passkeyRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Use case under test. */
    @InjectMocks
    private DeletePasskeyUseCase useCase;

    /**
     * Verifies that deleting a passkey is audited.
     */
    @Test
    void execute_whenPasskeyExists_deletesAndAudits() {
        final var userId = UUID.randomUUID();
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.delete(ID, HANDLE)).thenReturn(true);

        useCase.execute(userId, "alice", ID);

        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_REMOVED, userId, "alice",
                "passkey");
    }

    /**
     * Verifies that an account without any passkey cannot delete one.
     */
    @Test
    void execute_whenAccountHasNoEntity_throwsPasskeyNotFoundException() {
        final var userId = UUID.randomUUID();
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.empty());

        assertThrows(PasskeyNotFoundException.class, () -> useCase.execute(userId, "alice", ID));

        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that deleting a passkey that is not the account's is reported and not audited.
     */
    @Test
    void execute_whenPasskeyIsNotTheAccounts_throwsPasskeyNotFoundException() {
        final var userId = UUID.randomUUID();
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.delete(ID, HANDLE)).thenReturn(false);

        assertThrows(PasskeyNotFoundException.class, () -> useCase.execute(userId, "alice", ID));

        verifyNoInteractions(recordSecurityEventUseCase);
    }
}
