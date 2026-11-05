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

package com.irurueta.authserver.authorization.application.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyRepository;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ActiveSigningKeyUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ActiveSigningKeyUseCaseTest {

    /** Instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Port that stores the keys. */
    @Mock
    private SigningKeyRepository signingKeyRepository;

    /** Use case under test. */
    @InjectMocks
    private ActiveSigningKeyUseCase useCase;

    /**
     * Verifies that the active key is picked among the others.
     */
    @Test
    void execute_whenAnActiveKeyExists_returnsIt() {
        final var active = key("a", SigningKeyStatus.ACTIVE);
        when(signingKeyRepository.findAll()).thenReturn(List.of(key("n", SigningKeyStatus.NEXT), active));

        assertEquals(active, useCase.execute().orElseThrow());
    }

    /**
     * Verifies that an empty result is returned when no key is active.
     */
    @Test
    void execute_whenNoKeyIsActive_returnsEmpty() {
        when(signingKeyRepository.findAll()).thenReturn(List.of(key("n", SigningKeyStatus.NEXT)));

        assertTrue(useCase.execute().isEmpty());
    }

    /**
     * Creates a key.
     *
     * @param kid    identifier.
     * @param status state.
     * @return the key.
     */
    private static SigningKey key(final String kid, final SigningKeyStatus status) {
        return new SigningKey(kid, "RS256", "pub", "priv", status, NOW, null, null);
    }
}
