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
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
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
    @InjectMocks
    private DevDataInitializer initializer;

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
        verify(clients).save(DefaultClientDefinitions.bff(), ENCODED);
    }

    /**
     * Verifies that nothing is created when the user and the client already exist.
     */
    @Test
    void run_whenDataExists_doesNotCreateAnything() {
        userCount(1);
        when(clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID))
                .thenReturn(Optional.of(DefaultClientDefinitions.bff()));

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
        verify(clients).save(DefaultClientDefinitions.bff(), ENCODED);
    }

    /**
     * Verifies that only the user is created when the client already exists.
     */
    @Test
    void run_whenOnlyClientExists_createsOnlyUser() {
        userCount(0);
        when(encoder.encode(anyString())).thenReturn(ENCODED);
        when(clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID))
                .thenReturn(Optional.of(DefaultClientDefinitions.bff()));

        initializer.run(new DefaultApplicationArguments());

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
