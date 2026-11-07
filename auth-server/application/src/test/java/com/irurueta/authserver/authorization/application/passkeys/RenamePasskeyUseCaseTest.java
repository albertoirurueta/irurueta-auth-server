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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.passkeys.InvalidPasskeyLabelException;
import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RenamePasskeyUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RenamePasskeyUseCaseTest {

    /** User handle of the account. */
    private static final String HANDLE = "handle";

    /** Credential identifier. */
    private static final String ID = "cred";

    /** Port that stores the passkeys. */
    @Mock
    private PasskeyRepository passkeyRepository;

    /** Use case under test. */
    @InjectMocks
    private RenamePasskeyUseCase useCase;

    /**
     * Verifies that the label is trimmed, stored and the renamed passkey returned.
     */
    @Test
    void execute_whenPasskeyExists_renamesItAndReturnsIt() {
        final var renamed = new Passkey(ID, HANDLE, "Phone", Instant.EPOCH, null, 0L, false, false);
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.rename(ID, HANDLE, "Phone")).thenReturn(true);
        when(passkeyRepository.findByIdAndUserId(ID, HANDLE)).thenReturn(Optional.of(renamed));

        assertSame(renamed, useCase.execute("alice", ID, "  Phone "));

        verify(passkeyRepository).rename(ID, HANDLE, "Phone");
    }

    /**
     * Verifies that a blank or too long label is rejected before anything is read.
     */
    @Test
    void execute_whenLabelIsInvalid_throwsInvalidPasskeyLabelException() {
        final var tooLong = "x".repeat(RenamePasskeyUseCase.MAX_LABEL_LENGTH + 1);

        assertThrows(InvalidPasskeyLabelException.class, () -> useCase.execute("alice", ID, null));
        assertThrows(InvalidPasskeyLabelException.class, () -> useCase.execute("alice", ID, " "));
        assertThrows(InvalidPasskeyLabelException.class, () -> useCase.execute("alice", ID, tooLong));

        verifyNoInteractions(passkeyRepository);
    }

    /**
     * Verifies that a label of the maximum length once trimmed is accepted, the surrounding blanks not counting.
     */
    @Test
    void execute_whenTrimmedLabelHasMaximumLength_isAccepted() {
        final var longest = "y".repeat(RenamePasskeyUseCase.MAX_LABEL_LENGTH);
        final var renamed = new Passkey(ID, HANDLE, longest, Instant.EPOCH, null, 0L, false, false);
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.rename(ID, HANDLE, longest)).thenReturn(true);
        when(passkeyRepository.findByIdAndUserId(ID, HANDLE)).thenReturn(Optional.of(renamed));

        assertSame(renamed, useCase.execute("alice", ID, " " + longest + " "));
    }

    /**
     * Verifies that an account without any passkey cannot rename one.
     */
    @Test
    void execute_whenAccountHasNoEntity_throwsPasskeyNotFoundException() {
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.empty());

        assertThrows(PasskeyNotFoundException.class, () -> useCase.execute("alice", ID, "Phone"));
    }

    /**
     * Verifies that renaming a passkey that is not the account's is reported.
     */
    @Test
    void execute_whenPasskeyIsNotTheAccounts_throwsPasskeyNotFoundException() {
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.rename(ID, HANDLE, "Phone")).thenReturn(false);

        assertThrows(PasskeyNotFoundException.class, () -> useCase.execute("alice", ID, "Phone"));
    }

    /**
     * Verifies that a passkey that vanishes between the rename and the read is reported.
     */
    @Test
    void execute_whenPasskeyVanishesAfterRename_throwsPasskeyNotFoundException() {
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.rename(ID, HANDLE, "Phone")).thenReturn(true);
        when(passkeyRepository.findByIdAndUserId(ID, HANDLE)).thenReturn(Optional.empty());

        assertThrows(PasskeyNotFoundException.class, () -> useCase.execute("alice", ID, "Phone"));
    }
}
