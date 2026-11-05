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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyRepository;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ListSigningKeysUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ListSigningKeysUseCaseTest {

    /** Port that stores the keys. */
    @Mock
    private SigningKeyRepository signingKeyRepository;

    /** Use case under test. */
    @InjectMocks
    private ListSigningKeysUseCase useCase;

    /**
     * Verifies that every stored key is returned.
     */
    @Test
    void execute_whenCalled_returnsEveryKey() {
        final var keys = List.<SigningKey>of();
        when(signingKeyRepository.findAll()).thenReturn(keys);

        assertSame(keys, useCase.execute());
    }
}
