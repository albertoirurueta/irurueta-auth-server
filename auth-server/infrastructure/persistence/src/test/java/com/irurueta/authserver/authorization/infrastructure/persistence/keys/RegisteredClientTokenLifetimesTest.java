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

package com.irurueta.authserver.authorization.infrastructure.persistence.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RegisteredClientTokenLifetimes}.
 */
@ExtendWith(MockitoExtension.class)
class RegisteredClientTokenLifetimesTest {

    /** Number of minutes of a short access-token lifetime. */
    private static final long SHORT_MINUTES = 5;

    /** Number of hours of a long access-token lifetime. */
    private static final long LONG_HOURS = 12;

    /** Number of days of a long lifetime of reference (unsigned) access tokens. */
    private static final long REFERENCE_DAYS = 3;

    /** Port that stores the registered clients. */
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    /** Adapter under test. */
    @InjectMocks
    private RegisteredClientTokenLifetimes lifetimes;

    /**
     * Verifies that without clients the ID-token lifetime is the longest one.
     */
    @Test
    void longest_whenThereAreNoClients_returnsTheIdTokenLifetime() {
        when(clientRegistrationRepository.findAll()).thenReturn(List.of());

        assertEquals(RegisteredClientTokenLifetimes.ID_TOKEN_TTL, lifetimes.longest());
    }

    /**
     * Verifies that the longest self-contained access-token lifetime wins over the ID-token lifetime, and that
     * reference access tokens, never signed, are ignored.
     */
    @Test
    void longest_whenAClientHasLongerSignedAccessTokens_returnsItsLifetime() {
        when(clientRegistrationRepository.findAll()).thenReturn(List.of(
                client("short", Duration.ofMinutes(SHORT_MINUTES), ClientRegistration.FORMAT_SELF_CONTAINED),
                client("long", Duration.ofHours(LONG_HOURS), ClientRegistration.FORMAT_SELF_CONTAINED),
                client("opaque", Duration.ofDays(REFERENCE_DAYS), ClientRegistration.FORMAT_REFERENCE)));

        assertEquals(Duration.ofHours(LONG_HOURS), lifetimes.longest());
    }

    /**
     * Builds a client.
     *
     * @param clientId       client id.
     * @param accessTokenTtl lifetime of its access tokens.
     * @param format         format of its access tokens.
     * @return the client.
     */
    private static ClientRegistration client(final String clientId, final Duration accessTokenTtl,
                                             final String format) {
        return new ClientRegistration(clientId, "Client", true, List.of("client_secret_basic"),
                List.of("client_credentials"), List.of(), List.of("read"), true, List.of(), accessTokenTtl,
                Duration.ofHours(1), format, false);
    }
}
