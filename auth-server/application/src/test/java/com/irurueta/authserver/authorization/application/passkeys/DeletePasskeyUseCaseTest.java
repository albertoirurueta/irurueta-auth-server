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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
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

    /** Number of trusted devices revoked in the test. */
    private static final int REVOKED = 2;

    /** Port that stores the passkeys. */
    @Mock
    private PasskeyRepository passkeyRepository;

    /** Use case telling whether the user still has a confirmed second factor. */
    @Mock
    private HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Port that stores the trusted devices. */
    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Use case under test. */
    @InjectMocks
    private DeletePasskeyUseCase useCase;

    /**
     * Verifies that deleting a passkey while another second factor remains is audited and keeps the trusted devices.
     */
    @Test
    void execute_whenAnotherSecondFactorRemains_deletesAndAuditsKeepingTrustedDevices() {
        final var userId = UUID.randomUUID();
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.delete(ID, HANDLE)).thenReturn(true);
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);

        useCase.execute(userId, "alice", ID);

        verify(trustedDeviceRepository, never()).deleteByUser(userId);
        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_REMOVED, userId, "alice",
                "passkey");
    }

    /**
     * Verifies that deleting the last second factor revokes every trusted device and audits the count.
     */
    @Test
    void execute_whenNoSecondFactorRemains_revokesTrustedDevicesAndAuditsCount() {
        final var userId = UUID.randomUUID();
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.delete(ID, HANDLE)).thenReturn(true);
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(false);
        when(trustedDeviceRepository.deleteByUser(userId)).thenReturn(REVOKED);

        useCase.execute(userId, "alice", ID);

        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_REMOVED, userId, "alice",
                "passkey; trusted devices revoked: " + REVOKED);
    }

    /**
     * Verifies that an account without any passkey cannot delete one.
     */
    @Test
    void execute_whenAccountHasNoEntity_throwsPasskeyNotFoundException() {
        final var userId = UUID.randomUUID();
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.empty());

        assertThrows(PasskeyNotFoundException.class, () -> useCase.execute(userId, "alice", ID));

        verifyNoInteractions(recordSecurityEventUseCase, trustedDeviceRepository);
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

        verifyNoInteractions(recordSecurityEventUseCase, trustedDeviceRepository);
    }
}
