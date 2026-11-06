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

package com.irurueta.authserver.authorization.infrastructure.persistence.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Unit tests of {@link JdbcClientRegistrationRepository}, with the registered client repository, the JDBC client and
 * the mapper mocked. The mapping itself is covered by {@link RegisteredClientMapperTest}, and the mapping through the
 * real JDBC repository runs against PostgreSQL in {@link JdbcClientRegistrationRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcClientRegistrationRepositoryTest {

    /** Number of statements that delete a client: its authorizations, its consents and its row. */
    private static final int DELETE_STATEMENTS = 3;

    /** Client id used by the tests. */
    private static final String CLIENT_ID = "bff";

    /** Client id listed in the table whose client is no longer found. */
    private static final String GONE_CLIENT_ID = "gone";

    /** Internal identifier of the stored client. */
    private static final String ROW_ID = "row-id";

    /** Lifetime of access tokens used by the tests. */
    private static final Duration ACCESS_TTL = Duration.ofMinutes(10);

    /** Lifetime of refresh tokens used by the tests. */
    private static final Duration REFRESH_TTL = Duration.ofHours(8);

    /** Repository that maps registered clients to rows. */
    @Mock
    private RegisteredClientRepository registeredClientRepository;

    /** JDBC client that runs the other statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps between registrations and registered clients. */
    @Mock
    private RegisteredClientMapper registeredClientMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcClientRegistrationRepository repository;

    /**
     * Verifies that an empty result is returned, and nothing is mapped, when the client is not registered.
     */
    @Test
    void findByClientId_whenClientIsMissing_returnsEmpty() {
        assertTrue(repository.findByClientId(CLIENT_ID).isEmpty());

        verify(registeredClientMapper, never()).toRegistration(any());
    }

    /**
     * Verifies that a registered client is returned as the registration the mapper builds from it.
     */
    @Test
    void findByClientId_whenClientExists_returnsMappedRegistration() {
        final var registered = registeredClient(null);
        final var registration = registration();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registered);
        when(registeredClientMapper.toRegistration(registered)).thenReturn(registration);

        assertSame(registration, repository.findByClientId(CLIENT_ID).orElseThrow());
    }

    /**
     * Verifies that every client id of the table is loaded through the registered client repository, skipping the
     * ones that are no longer found.
     */
    @Test
    void findAll_whenClientsExist_returnsAllRegistrations() {
        final var registered = registeredClient(null);
        final var registration = registration();
        when(client.sql(any(String.class)).query(String.class).list()).thenReturn(List.of(CLIENT_ID, GONE_CLIENT_ID));
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registered);
        when(registeredClientMapper.toRegistration(registered)).thenReturn(registration);

        assertEquals(List.of(registration), repository.findAll());
    }

    /**
     * Verifies that a new client is mapped with a generated identifier, an issue instant and the given secret, and
     * that the mapped client is stored.
     */
    @Test
    void save_whenClientIsNew_storesTheMappedClient() {
        final var registration = registration();
        final var secret = encoded();
        final var mapped = registeredClient(secret);
        when(registeredClientMapper.toRegisteredClient(eq(registration), any(String.class), any(Instant.class),
                eq(secret))).thenReturn(mapped);

        repository.save(registration, secret);

        final var id = ArgumentCaptor.<String>captor();
        verify(registeredClientMapper).toRegisteredClient(eq(registration), id.capture(), any(Instant.class),
                eq(secret));
        assertNotNull(UUID.fromString(id.getValue()));
        verify(registeredClientRepository).save(mapped);
    }

    /**
     * Verifies that saving an existing client with a null secret keeps its identifier, issue instant and secret.
     */
    @Test
    void save_whenClientExistsAndSecretIsNull_keepsStoredSecretAndIdentifier() {
        final var issuedAt = Instant.parse("2025-06-01T00:00:00Z");
        final var storedValue = encoded();
        final var existing = RegisteredClient.withId(ROW_ID).clientId(CLIENT_ID).clientIdIssuedAt(issuedAt)
                .clientSecret(storedValue)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        final var registration = registration();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(existing);
        when(registeredClientMapper.toRegisteredClient(registration, ROW_ID, issuedAt, storedValue))
                .thenReturn(existing);

        repository.save(registration, null);

        verify(registeredClientRepository).save(existing);
    }

    /**
     * Verifies that saving an existing client with a new secret replaces the secret but keeps the identifier.
     */
    @Test
    void save_whenClientExistsAndSecretIsGiven_replacesTheSecret() {
        final var existing = registeredClient(encoded());
        final var registration = registration();
        final var secret = encoded();
        final var mapped = registeredClient(secret);
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(existing);
        when(registeredClientMapper.toRegisteredClient(eq(registration), eq(ROW_ID), any(Instant.class),
                eq(secret))).thenReturn(mapped);

        repository.save(registration, secret);

        verify(registeredClientRepository).save(mapped);
    }

    /**
     * Verifies that the client is deleted by its client id.
     */
    @Test
    void deleteByClientId_whenCalled_deletesAuthorizationsConsentsAndTheRow() {
        repository.deleteByClientId(CLIENT_ID);

        final var statements = ArgumentCaptor.<String>captor();
        verify(client, times(DELETE_STATEMENTS)).sql(statements.capture());
        assertEquals(List.of("DELETE FROM oauth2_authorization ", "DELETE FROM oauth2_authorization_consent ",
                        "DELETE FROM oauth2_registered_client "),
                statements.getAllValues().stream().map(sql -> sql.substring(0, sql.indexOf("WHERE"))).toList());
    }

    /**
     * Verifies that the secret is replaced for the client id.
     */
    @Test
    void updateSecret_whenCalled_updatesTheRow() {
        final var value = encoded();

        repository.updateSecret(CLIENT_ID, value);

        verify(client.sql(any(String.class)).params(value, CLIENT_ID)).update();
    }

    /**
     * Builds a runtime-generated placeholder for an encoded value.
     *
     * @return the placeholder.
     */
    private static String encoded() {
        return "encoded-" + UUID.randomUUID();
    }

    /**
     * Builds a registered client stored under {@link #ROW_ID}.
     *
     * @param secret encoded secret, or {@code null}.
     * @return the registered client.
     */
    private static RegisteredClient registeredClient(final String secret) {
        return RegisteredClient.withId(ROW_ID).clientId(CLIENT_ID).clientSecret(secret)
                .clientIdIssuedAt(Instant.now())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    /**
     * Builds a confidential registration.
     *
     * @return the registration.
     */
    private static ClientRegistration registration() {
        return new ClientRegistration(CLIENT_ID, "Backend for Frontend", true, List.of("client_secret_basic"),
                List.of("client_credentials"), List.of(), List.of("openid"), true, List.of(), ACCESS_TTL,
                REFRESH_TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false);
    }
}
