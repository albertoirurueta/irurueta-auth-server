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
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RotateClientSecretUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RotateClientSecretUseCaseTest {

    /** Redirect URI of the default clients built by the tests. */
    private static final String TEST_REDIRECT_URI = "https://app.example.test/callback";

    /** Access token lifetime of the key-based client. */
    private static final Duration ACCESS_TTL = Duration.ofMinutes(5);

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
    private RotateClientSecretUseCase useCase;

    /**
     * Verifies that a confidential client gets a new encoded secret and the clear one is returned.
     */
    @Test
    void execute_whenClientIsConfidential_storesNewEncodedSecret() {
        when(clientRegistrationRepository.findByClientId("bff"))
                .thenReturn(Optional.of(bff()));
        when(clientSecretGenerator.generate()).thenReturn(SECRET);
        when(passwordHasher.encode(SECRET)).thenReturn(ENCODED);

        assertEquals(SECRET, useCase.execute("bff"));

        verify(clientRegistrationRepository).updateSecret("bff", ENCODED);
    }

    /**
     * Verifies that an unknown client is rejected.
     */
    @Test
    void execute_whenClientIsMissing_throwsClientNotFoundException() {
        when(clientRegistrationRepository.findByClientId("bff")).thenReturn(Optional.empty());

        assertThrows(ClientNotFoundException.class, () -> useCase.execute("bff"));
    }

    /**
     * Verifies that a public client, which has no secret, is rejected.
     */
    @Test
    void execute_whenClientIsPublic_throwsIllegalArgumentException() {
        when(clientRegistrationRepository.findByClientId("spa-public"))
                .thenReturn(Optional.of(spaPublic()));

        assertThrows(IllegalArgumentException.class, () -> useCase.execute("spa-public"));

        verify(clientRegistrationRepository, never()).updateSecret(any(), any());
    }

    /**
     * Verifies that a client without a {@code client_secret_*} method cannot have its secret rotated.
     */
    @Test
    void execute_whenClientUsesPrivateKeyJwtOnly_throwsIllegalArgumentException() {
        when(clientRegistrationRepository.findByClientId("service"))
                .thenReturn(Optional.of(privateKeyJwtClient()));

        assertThrows(IllegalArgumentException.class, () -> useCase.execute("service"));

        verify(clientRegistrationRepository, never()).updateSecret(any(), any());
        verify(clientSecretGenerator, never()).generate();
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

    /**
     * Builds a confidential client that authenticates with {@code private_key_jwt} only.
     *
     * @return the client.
     */
    private static ClientRegistration privateKeyJwtClient() {
        return new ClientRegistration("service", "Service", true, List.of("private_key_jwt"),
                List.of("client_credentials"), List.of(), List.of("documents.read"), false, List.of(),
                ACCESS_TTL, Duration.ofDays(1), ClientRegistration.FORMAT_SELF_CONTAINED, false,
                List.of(), false, false, "https://client.example.test/jwks.json", null, null, null, false);
    }
}
