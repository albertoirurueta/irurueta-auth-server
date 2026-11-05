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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientAlreadyExistsException;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link CreateClientUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class CreateClientUseCaseTest {

    /** Redirect URI of the default clients built by the tests. */
    private static final String TEST_REDIRECT_URI = "https://app.example.test/callback";

    /** Generated secret returned by the mocked generator. */
    private static final String SECRET = "generated-secret";

    /** Encoded secret returned by the mocked hasher. */
    private static final String ENCODED = "{argon2}encoded";

    /** Port that stores the clients. */
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    /** Port that encodes secrets. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Generator of client secrets. */
    @Mock
    private ClientSecretGenerator clientSecretGenerator;

    /** Use case under test. */
    @InjectMocks
    private CreateClientUseCase useCase;

    /**
     * Verifies that a confidential client is stored with its encoded secret and the clear secret is returned.
     */
    @Test
    void execute_whenClientIsConfidential_storesEncodedSecretAndReturnsClearOne() {
        final var bff = bff();
        when(clientRegistrationRepository.findByClientId(bff.clientId())).thenReturn(Optional.empty());
        when(clientSecretGenerator.generate()).thenReturn(SECRET);
        when(passwordHasher.encode(SECRET)).thenReturn(ENCODED);

        final var created = useCase.execute(bff);

        assertEquals(SECRET, created.clientSecret());
        assertEquals(bff, created.registration());
        verify(clientRegistrationRepository).save(bff, ENCODED);
    }

    /**
     * Verifies that a public client gets no secret.
     */
    @Test
    void execute_whenClientIsPublic_storesNoSecret() {
        final var spa = spaPublic();
        when(clientRegistrationRepository.findByClientId(spa.clientId())).thenReturn(Optional.empty());

        final var created = useCase.execute(spa);

        assertNull(created.clientSecret());
        verify(clientRegistrationRepository).save(spa, null);
    }

    /**
     * Verifies that an existing client id is rejected.
     */
    @Test
    void execute_whenClientExists_throwsClientAlreadyExistsException() {
        final var bff = bff();
        when(clientRegistrationRepository.findByClientId(bff.clientId())).thenReturn(Optional.of(bff));

        assertThrows(ClientAlreadyExistsException.class, () -> useCase.execute(bff));

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
     * Builds the default {@code spa-public} client with a test redirect URI.
     *
     * @return the client.
     */
    private static ClientRegistration spaPublic() {
        return DefaultClientDefinitions.spaPublic(List.of(TEST_REDIRECT_URI),
                DefaultClientDefinitions.DEFAULT_API_AUDIENCE);
    }
}
