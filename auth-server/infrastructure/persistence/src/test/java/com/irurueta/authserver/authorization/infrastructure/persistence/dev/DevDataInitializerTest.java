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

package com.irurueta.authserver.authorization.infrastructure.persistence.dev;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Unit tests of {@link DevDataInitializer}, with the database and the client repository mocked.
 */
@ExtendWith(MockitoExtension.class)
class DevDataInitializerTest {

    /** Statement that inserts the demo user. */
    private static final String INSERT_USER = "INSERT INTO users (id, username) VALUES (?, ?)";

    /** Result of the mocked password encoder; not a real credential. */
    private static final String ENCODED = "encoded";

    /** Redirect URIs configured for the BFF client. */
    private static final List<String> REDIRECT_URIS = List.of("http://localhost:8080/login/oauth2/code/bff");

    /** The BFF client the initializer creates from the configured values. */
    private static final ClientRegistration BFF = DefaultClientDefinitions.bff(REDIRECT_URIS,
            DefaultClientDefinitions.DEFAULT_API_AUDIENCE);

    /** JDBC client that stores the demo user. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient jdbc;

    /** Encoder of the generated secrets. */
    @Mock
    private PasswordEncoder encoder;

    /** Repository where the BFF client is stored. */
    @Mock
    private ClientRegistrationRepository clients;

    /** Initializer under test. */
    private DevDataInitializer initializer;

    /**
     * Creates the initializer with the mocks and the configured BFF values; the configured values are no mocks, so
     * the initializer cannot be injected.
     */
    @BeforeEach
    void setUp() {
        initializer = new DevDataInitializer(jdbc, encoder, clients, REDIRECT_URIS,
                DefaultClientDefinitions.DEFAULT_API_AUDIENCE);
    }

    /**
     * Verifies that the user and the client are created when nothing exists yet.
     */
    @Test
    void run_whenNothingExists_createsUserAndClient() {
        userCount(0);
        when(clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID)).thenReturn(Optional.empty());
        when(encoder.encode(anyString())).thenReturn(ENCODED);

        initializer.run(new DefaultApplicationArguments());

        verify(jdbc).sql(INSERT_USER);
        verify(clients).save(BFF, ENCODED);
    }

    /**
     * Verifies that nothing is created when the user and the client already exist.
     */
    @Test
    void run_whenDataExists_doesNotCreateAnything() {
        userCount(1);
        when(clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID))
                .thenReturn(Optional.of(BFF));

        initializer.run(new DefaultApplicationArguments());

        verify(jdbc, never()).sql(INSERT_USER);
        verify(clients, never()).save(any(), any());
    }

    /**
     * Verifies that only the client is created when the user already exists.
     */
    @Test
    void run_whenOnlyUserExists_createsOnlyClient() {
        userCount(1);
        when(clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID)).thenReturn(Optional.empty());
        when(encoder.encode(anyString())).thenReturn(ENCODED);

        initializer.run(new DefaultApplicationArguments());

        verify(jdbc, never()).sql(INSERT_USER);
        verify(clients).save(BFF, ENCODED);
    }

    /**
     * Verifies that only the user is created when the client already exists.
     */
    @Test
    void run_whenOnlyClientExists_createsOnlyUser() {
        userCount(0);
        when(encoder.encode(anyString())).thenReturn(ENCODED);
        when(clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID))
                .thenReturn(Optional.of(BFF));

        initializer.run(new DefaultApplicationArguments());

        verify(jdbc).sql(INSERT_USER);
        verify(clients, never()).save(any(), any());
    }

    /**
     * Verifies that the client is not created when no redirect URI is configured, while the user still is.
     */
    @Test
    void run_whenNoRedirectUriIsConfigured_createsOnlyUser() {
        userCount(0);
        when(encoder.encode(anyString())).thenReturn(ENCODED);
        when(clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID)).thenReturn(Optional.empty());
        final var unconfigured = new DevDataInitializer(jdbc, encoder, clients, List.of(),
                DefaultClientDefinitions.DEFAULT_API_AUDIENCE);

        unconfigured.run(new DefaultApplicationArguments());

        verify(jdbc).sql(INSERT_USER);
        verify(clients, never()).save(any(), any());
    }

    /**
     * Makes the mocked database report how many demo users exist.
     *
     * @param count number of demo users.
     */
    private void userCount(final int count) {
        when(jdbc.sql(anyString()).param(DevDataInitializer.DEMO_USERNAME).query(Integer.class).single())
                .thenReturn(count);
    }
}
