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

package com.irurueta.authserver.authorization.api.web.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import com.irurueta.authserver.authorization.application.clients.SeedResult;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;

/**
 * Unit tests of {@link ClientSeeder}.
 */
@ExtendWith(MockitoExtension.class)
class ClientSeederTest {

    /** Seeds the clients. */
    @Mock
    private SeedRegisteredClientsUseCase seedRegisteredClientsUseCase;

    /**
     * A configured secret is handed to the use case under the bff client identifier.
     */
    @Test
    void run_whenSecretIsConfigured_passesItToTheUseCase() {
        final var secret = UUID.randomUUID().toString();
        when(seedRegisteredClientsUseCase.execute(any())).thenReturn(new SeedResult(List.of("bff"), List.of()));

        new ClientSeeder(seedRegisteredClientsUseCase, new ClientSeedProperties(secret))
                .run(mock(ApplicationArguments.class));

        final var captor = ArgumentCaptor.<Map<String, String>>captor();
        verify(seedRegisteredClientsUseCase).execute(captor.capture());
        assertEquals(Map.of("bff", secret), captor.getValue());
    }

    /**
     * Without a configured secret the use case gets no secrets.
     */
    @Test
    void run_whenSecretIsEmpty_passesNoSecrets() {
        when(seedRegisteredClientsUseCase.execute(any())).thenReturn(new SeedResult(List.of(), List.of("bff")));

        new ClientSeeder(seedRegisteredClientsUseCase, new ClientSeedProperties(""))
                .run(mock(ApplicationArguments.class));

        verify(seedRegisteredClientsUseCase).execute(Map.of());
    }
}
