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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link SeedRegisteredClientsUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class SeedRegisteredClientsUseCaseTest {

    /** Clear-text secret used by the tests; not a real credential. */
    private static final String SECRET = "from-environment";

    /** Encoded secret returned by the mocked hasher. */
    private static final String ENCODED = "{argon2}encoded";

    /** Port that stores the clients. */
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    /** Port that encodes secrets. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Use case under test. */
    @InjectMocks
    private SeedRegisteredClientsUseCase useCase;

    /**
     * Verifies that both missing clients are created, the confidential one with an encoded secret.
     */
    @Test
    void execute_whenNoClientExists_createsBoth() {
        when(clientRegistrationRepository.findByClientId(any())).thenReturn(Optional.empty());
        when(passwordHasher.encode(SECRET)).thenReturn(ENCODED);

        final var created = useCase.execute(Map.of("bff", SECRET));

        assertEquals(List.of("bff", "spa-public"), created.created());
        assertTrue(created.skipped().isEmpty());
        verify(clientRegistrationRepository).save(DefaultClientDefinitions.bff(), ENCODED);
        verify(clientRegistrationRepository).save(DefaultClientDefinitions.spaPublic(), null);
    }

    /**
     * Verifies that running again changes nothing.
     */
    @Test
    void execute_whenClientsExist_createsNothing() {
        when(clientRegistrationRepository.findByClientId("bff"))
                .thenReturn(Optional.of(DefaultClientDefinitions.bff()));
        when(clientRegistrationRepository.findByClientId("spa-public"))
                .thenReturn(Optional.of(DefaultClientDefinitions.spaPublic()));

        assertTrue(useCase.execute(Map.of()).created().isEmpty());

        verify(clientRegistrationRepository, never()).save(any(), any());
    }

    /**
     * Verifies that a missing secret skips the confidential client but still seeds the public one.
     */
    @Test
    void execute_whenSecretIsMissing_skipsConfidentialClientAndSeedsTheOthers() {
        when(clientRegistrationRepository.findByClientId(any())).thenReturn(Optional.empty());

        final var created = useCase.execute(Map.of());

        assertEquals(List.of("spa-public"), created.created());
        assertEquals(List.of("bff"), created.skipped());
        verify(clientRegistrationRepository).save(DefaultClientDefinitions.spaPublic(), null);
        verify(clientRegistrationRepository, never()).save(eq(DefaultClientDefinitions.bff()), any());
    }

    /**
     * Verifies that a blank secret is treated like a missing one.
     */
    @Test
    void execute_whenSecretIsBlank_skipsConfidentialClient() {
        when(clientRegistrationRepository.findByClientId(any())).thenReturn(Optional.empty());

        final var created = useCase.execute(Map.of("bff", " "));

        assertEquals(List.of("spa-public"), created.created());
        assertEquals(List.of("bff"), created.skipped());
        verify(passwordHasher, never()).encode(any());
    }
}
