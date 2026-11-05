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

import com.irurueta.authserver.authorization.api.web.clients.ClientSeedProperties.SeededClient;
import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import com.irurueta.authserver.authorization.application.clients.SeedResult;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
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

    /** Redirect URI configured for the BFF. */
    private static final String BFF_URI = "https://bff.example.test/login/oauth2/code/bff";

    /** Redirect URI configured for the single-page application. */
    private static final String SPA_URI = "https://spa.example.test/callback";

    /** Audience of the authorization server's API. */
    private static final String API_AUDIENCE = "auth-server";

    /** Seeds the clients. */
    @Mock
    private SeedRegisteredClientsUseCase seedRegisteredClientsUseCase;

    /**
     * Both configured clients are built from their definitions with the configured redirect URIs and the API
     * audience, and a configured secret is handed to the use case under the bff client identifier.
     */
    @Test
    void run_whenBothClientsAndTheSecretAreConfigured_seedsBoth() {
        final var secret = UUID.randomUUID().toString();
        when(seedRegisteredClientsUseCase.execute(any(), any()))
                .thenReturn(new SeedResult(List.of("bff", "spa-public"), List.of()));

        seeder(new ClientSeedProperties(secret, new SeededClient(List.of(BFF_URI)),
                new SeededClient(List.of(SPA_URI)))).run(mock(ApplicationArguments.class));

        final var definitions = ArgumentCaptor.<List<ClientRegistration>>captor();
        final var secrets = ArgumentCaptor.<Map<String, String>>captor();
        verify(seedRegisteredClientsUseCase).execute(definitions.capture(), secrets.capture());
        assertEquals(List.of(DefaultClientDefinitions.bff(List.of(BFF_URI), API_AUDIENCE),
                DefaultClientDefinitions.spaPublic(List.of(SPA_URI), API_AUDIENCE)), definitions.getValue());
        assertEquals(Map.of("bff", secret), secrets.getValue());
    }

    /**
     * Without any configured client nothing is seeded, and no {@code localhost} default slips in.
     */
    @Test
    void run_whenNoClientIsConfigured_seedsNothing() {
        when(seedRegisteredClientsUseCase.execute(any(), any())).thenReturn(new SeedResult(List.of(), List.of()));

        seeder(new ClientSeedProperties(null, null, null)).run(mock(ApplicationArguments.class));

        verify(seedRegisteredClientsUseCase).execute(List.of(), Map.of());
    }

    /**
     * Only the configured client is seeded: {@code spa-public} is left out unless it is configured, and without a
     * secret the use case gets no secrets.
     */
    @Test
    void run_whenOnlyTheBffIsConfiguredWithoutSecret_passesOnlyTheBffAndNoSecrets() {
        when(seedRegisteredClientsUseCase.execute(any(), any())).thenReturn(new SeedResult(List.of(), List.of("bff")));

        seeder(new ClientSeedProperties("", new SeededClient(List.of(BFF_URI)), SeededClient.unconfigured()))
                .run(mock(ApplicationArguments.class));

        verify(seedRegisteredClientsUseCase).execute(
                List.of(DefaultClientDefinitions.bff(List.of(BFF_URI), API_AUDIENCE)), Map.of());
    }

    /**
     * Creates the seeder under test.
     *
     * @param properties seed configuration.
     * @return the seeder.
     */
    private ClientSeeder seeder(final ClientSeedProperties properties) {
        return new ClientSeeder(seedRegisteredClientsUseCase, properties, API_AUDIENCE);
    }
}
