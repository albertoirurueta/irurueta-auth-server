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

package com.irurueta.authserver.authorization.application.clients;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.clients.ClientNotFoundException;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link DeleteClientUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class DeleteClientUseCaseTest {

    /** Port that stores the clients. */
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    /** Use case under test. */
    @InjectMocks
    private DeleteClientUseCase useCase;

    /**
     * Verifies that an existing client is deleted.
     */
    @Test
    void execute_whenClientExists_deletesIt() {
        when(clientRegistrationRepository.findByClientId("bff"))
                .thenReturn(Optional.of(DefaultClientDefinitions.bff()));

        useCase.execute("bff");

        verify(clientRegistrationRepository).deleteByClientId("bff");
    }

    /**
     * Verifies that an unknown client is rejected.
     */
    @Test
    void execute_whenClientIsMissing_throwsClientNotFoundException() {
        when(clientRegistrationRepository.findByClientId("bff")).thenReturn(Optional.empty());

        assertThrows(ClientNotFoundException.class, () -> useCase.execute("bff"));

        verify(clientRegistrationRepository, never()).deleteByClientId("bff");
    }
}
