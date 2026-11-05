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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.util.List;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link GetClientUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class GetClientUseCaseTest {

    /** Redirect URI of the default clients built by the tests. */
    private static final String TEST_REDIRECT_URI = "https://app.example.test/callback";

    /** Port that stores the clients. */
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    /** Use case under test. */
    @InjectMocks
    private GetClientUseCase useCase;

    /**
     * Verifies that the stored client is returned.
     */
    @Test
    void execute_whenCalled_returnsWhatTheRepositoryFinds() {
        final var bff = Optional.of(bff());
        when(clientRegistrationRepository.findByClientId("bff")).thenReturn(bff);

        assertEquals(bff, useCase.execute("bff"));
    }

    /**
     * Builds the default {@code bff} client with a test redirect URI.
     *
     * @return the client.
     */
    private static ClientRegistration bff() {
        return DefaultClientDefinitions.bff(List.of(TEST_REDIRECT_URI), DefaultClientDefinitions.DEFAULT_API_AUDIENCE);
    }
}
