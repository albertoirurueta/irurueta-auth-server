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
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
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

    /** Port that reads the passkeys. */
    @Mock
    private PasskeyRepository passkeyRepository;

    /** Use case under test. */
    @InjectMocks
    private HasConfirmedPasskeyUseCase useCase;

    /**
     * Verifies that a user with a passkey is enrolled, through both entry points.
     */
    @Test
    void execute_whenUserHasAPasskey_returnsTrue() {
        final var userId = UUID.randomUUID();
        when(passkeyRepository.existsForAccount(userId)).thenReturn(true);

        assertTrue(useCase.execute(userId));
        assertTrue(useCase.hasConfirmed(userId));
    }

    /**
     * Verifies that a user without any passkey is not enrolled.
     */
    @Test
    void hasConfirmed_whenUserHasNoPasskey_returnsFalse() {
        final var userId = UUID.randomUUID();
        when(passkeyRepository.existsForAccount(userId)).thenReturn(false);

        assertFalse(useCase.hasConfirmed(userId));
    }
}
