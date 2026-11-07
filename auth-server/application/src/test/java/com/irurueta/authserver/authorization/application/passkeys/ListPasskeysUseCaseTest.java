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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ListPasskeysUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ListPasskeysUseCaseTest {

    /** User handle of the account. */
    private static final String HANDLE = "handle";

    /** Port that reads the passkeys. */
    @Mock
    private PasskeyRepository passkeyRepository;

    /** Use case under test. */
    @InjectMocks
    private ListPasskeysUseCase useCase;

    /**
     * Verifies that the passkeys of the account are returned.
     */
    @Test
    void execute_whenAccountHasPasskeys_returnsThem() {
        final var passkeys = List.of(new Passkey("id", HANDLE, "Laptop", Instant.EPOCH, null, 0L, false, false));
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.of(HANDLE));
        when(passkeyRepository.findByUserId(HANDLE)).thenReturn(passkeys);

        assertSame(passkeys, useCase.execute("alice"));
    }

    /**
     * Verifies that an account that never registered a passkey has an empty list.
     */
    @Test
    void execute_whenAccountHasNoEntity_returnsEmptyList() {
        when(passkeyRepository.findUserIdByUsername("alice")).thenReturn(Optional.empty());

        assertTrue(useCase.execute("alice").isEmpty());
    }
}
