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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

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
    private RegisteredClientRepository clients;

    /** Initializer under test. */
    @InjectMocks
    private DevDataInitializer initializer;

    /**
     * Verifies that the user and the client are created when nothing exists yet.
     */
    @Test
    void run_whenNothingExists_createsUserAndClient() {
        userCount(0);
        when(encoder.encode(anyString())).thenReturn(ENCODED);

        initializer.run(new DefaultApplicationArguments());

        verify(jdbc).sql(INSERT_USER);
        final var captor = ArgumentCaptor.<RegisteredClient>captor();
        verify(clients).save(captor.capture());
        final var client = captor.getValue();
        assertEquals(DevDataInitializer.BFF_CLIENT_ID, client.getClientId());
        assertEquals(ENCODED, client.getClientSecret());
        assertTrue(client.getClientSettings().isRequireProofKey());
        assertEquals(Set.of(DevDataInitializer.BFF_REDIRECT_URI), client.getRedirectUris());
        assertEquals(Set.of("openid", "profile"), client.getScopes());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN),
                client.getAuthorizationGrantTypes());
    }

    /**
     * Verifies that nothing is created when the user and the client already exist.
     */
    @Test
    void run_whenDataExists_doesNotCreateAnything() {
        userCount(1);
        when(clients.findByClientId(DevDataInitializer.BFF_CLIENT_ID)).thenReturn(existingClient());

        initializer.run(new DefaultApplicationArguments());

        verify(jdbc, never()).sql(INSERT_USER);
        verify(clients, never()).save(any(RegisteredClient.class));
    }

    /**
     * Verifies that only the client is created when the user already exists.
     */
    @Test
    void run_whenOnlyUserExists_createsOnlyClient() {
        userCount(1);
        when(encoder.encode(anyString())).thenReturn(ENCODED);

        initializer.run(new DefaultApplicationArguments());

        verify(jdbc, never()).sql(INSERT_USER);
        verify(clients).save(any(RegisteredClient.class));
    }

    /**
     * Verifies that only the user is created when the client already exists.
     */
    @Test
    void run_whenOnlyClientExists_createsOnlyUser() {
        userCount(0);
        when(encoder.encode(anyString())).thenReturn(ENCODED);
        when(clients.findByClientId(DevDataInitializer.BFF_CLIENT_ID)).thenReturn(existingClient());

        initializer.run(new DefaultApplicationArguments());

        verify(jdbc).sql(INSERT_USER);
        verify(clients, never()).save(any(RegisteredClient.class));
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

    /**
     * Creates a client as the repository would return it.
     *
     * @return the client.
     */
    private static RegisteredClient existingClient() {
        return RegisteredClient.withId("existing").clientId(DevDataInitializer.BFF_CLIENT_ID)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
    }
}
