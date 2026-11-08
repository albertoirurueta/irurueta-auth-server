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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.List;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientNotFoundException;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.clients.ImplicitClientRefusedException;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link UpdateClientUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class UpdateClientUseCaseTest {

    /** Redirect URI of the default clients built by the tests. */
    private static final String TEST_REDIRECT_URI = "https://app.example.test/callback";

    /** Token lifetime of the implicit client. */
    private static final Duration IMPLICIT_TTL = Duration.ofMinutes(15);

    /** Port that stores the clients. */
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    /** Use case under test. */
    @InjectMocks
    private UpdateClientUseCase useCase;

    /**
     * Verifies that an existing client is saved without touching its secret.
     */
    @Test
    void execute_whenClientExists_savesItKeepingTheSecret() {
        final var bff = bff();
        when(clientRegistrationRepository.findByClientId(bff.clientId())).thenReturn(Optional.of(bff));

        useCase.execute(bff);

        verify(clientRegistrationRepository).save(bff, null);
    }

    /**
     * Verifies that an unknown client is rejected.
     */
    @Test
    void execute_whenClientIsMissing_throwsClientNotFoundException() {
        final var bff = bff();
        when(clientRegistrationRepository.findByClientId(bff.clientId())).thenReturn(Optional.empty());

        assertThrows(ClientNotFoundException.class, () -> useCase.execute(bff));

        verify(clientRegistrationRepository, never()).save(any(), any());
    }

    /**
     * Verifies that a client with the implicit grant is refused before anything is looked up or stored.
     */
    @Test
    void execute_whenClientUsesImplicit_throwsImplicitClientRefusedException() {
        final var client = implicitClient();

        assertThrows(ImplicitClientRefusedException.class, () -> useCase.execute(client));

        verify(clientRegistrationRepository, never()).findByClientId(any());
        verify(clientRegistrationRepository, never()).save(any(), any());
    }

    /**
     * Builds the default {@code bff} client with a test redirect URI.
     *
     * @return the client.
     */
    private static ClientRegistration bff() {
        return DefaultClientDefinitions.bff(List.of(TEST_REDIRECT_URI), DefaultClientDefinitions.DEFAULT_API_AUDIENCE);
    }

    /**
     * Builds a public client with the legacy implicit grant, as the legacy demo seeds it.
     *
     * @return the client.
     */
    private static ClientRegistration implicitClient() {
        return new ClientRegistration("legacy-implicit-spa", "Legacy", false, List.of("none"), List.of("implicit"),
                List.of(TEST_REDIRECT_URI), List.of("documents.read"), false, List.of(), IMPLICIT_TTL,
                IMPLICIT_TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false,
                null, null, null, null, false);
    }
}
