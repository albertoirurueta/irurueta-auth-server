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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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
import org.springframework.transaction.annotation.Transactional;

/**
 * Unit tests of {@link JdbcClientRegistrationRepository}, with the registered client repository and the JDBC
 * client mocked. The mapping through the real JDBC repository runs against PostgreSQL in
 * {@link JdbcClientRegistrationRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcClientRegistrationRepositoryTest {

    /** Number of statements that delete a client: its authorizations, its consents and its row. */
    private static final int DELETE_STATEMENTS = 3;

    /** Client id used by the tests. */
    private static final String CLIENT_ID = "bff";

    /** Audience used by the tests. */
    private static final String AUDIENCE = "resource-server";

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

    /** Repository under test. */
    @InjectMocks
    private JdbcClientRegistrationRepository repository;

    /**
     * Verifies that an empty result is returned when the client is not registered.
     */
    @Test
    void findByClientId_whenClientIsMissing_returnsEmpty() {
        assertTrue(repository.findByClientId(CLIENT_ID).isEmpty());
    }

    /**
     * Verifies that a client saved by the repository is read back as the same registration.
     */
    @Test
    void findByClientId_whenClientWasSaved_roundTripsTheRegistration() {
        final var registration = confidential();
        final var saved = save(registration, encoded());
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(saved);

        assertEquals(registration, repository.findByClientId(CLIENT_ID).orElseThrow());
    }

    /**
     * Verifies that a public client round-trips as public, with no client authentication.
     */
    @Test
    void findByClientId_whenClientIsPublic_isNotConfidential() {
        final var registration = new ClientRegistration("spa", "Single-page application", false, List.of("none"),
                List.of("authorization_code"), List.of("http://localhost:3000/callback"), List.of("openid"), true,
                List.of(AUDIENCE), ACCESS_TTL, REFRESH_TTL, ClientRegistration.FORMAT_REFERENCE, true);
        final var saved = save(registration, null);
        when(registeredClientRepository.findByClientId("spa")).thenReturn(saved);

        final var found = repository.findByClientId("spa").orElseThrow();

        assertFalse(found.confidential());
        assertEquals(registration, found);
    }

    /**
     * Verifies that every client id of the table is loaded through the registered client repository.
     */
    @Test
    void findAll_whenClientsExist_returnsAllRegistrations() {
        final var first = save(confidential(), encoded());
        when(client.sql(any(String.class)).query(String.class).list()).thenReturn(List.of(CLIENT_ID, "gone"));
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(first);

        final var all = repository.findAll();

        assertEquals(List.of(confidential()), all);
    }

    /**
     * Verifies that a new client is stored with a generated identifier, the given secret, its audiences as a
     * custom setting and its token settings.
     */
    @Test
    void save_whenClientIsNew_storesTheMappedClient() {
        final var storedValue = encoded();

        final var stored = save(confidential(), storedValue);

        assertNotNull(stored.getId());
        assertEquals(storedValue, stored.getClientSecret());
        assertEquals(List.of(AUDIENCE), stored.getClientSettings().getSetting(
                JdbcClientRegistrationRepository.AUDIENCES_SETTING));
        assertTrue(stored.getClientSettings().isRequireProofKey());
        assertEquals(ACCESS_TTL, stored.getTokenSettings().getAccessTokenTimeToLive());
        assertEquals(REFRESH_TTL, stored.getTokenSettings().getRefreshTokenTimeToLive());
        assertFalse(stored.getTokenSettings().isReuseRefreshTokens());
    }

    /**
     * Verifies that saving an existing client with a null secret keeps its identifier, issue instant and secret.
     */
    @Test
    void save_whenClientExistsAndSecretIsNull_keepsStoredSecretAndIdentifier() {
        final var issuedAt = Instant.parse("2025-06-01T00:00:00Z");
        final var storedValue = encoded();
        final var existing = RegisteredClient.withId("row-id").clientId(CLIENT_ID).clientIdIssuedAt(issuedAt)
                .clientSecret(storedValue).clientAuthenticationMethod(
                        new ClientAuthenticationMethod("client_secret_basic"))
                .authorizationGrantType(
                        new AuthorizationGrantType("client_credentials"))
                .build();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(existing);

        final var stored = save(confidential(), null);

        assertEquals("row-id", stored.getId());
        assertEquals(storedValue, stored.getClientSecret());
        assertEquals(issuedAt, stored.getClientIdIssuedAt());
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
     * Verifies that the three deletions run in one transaction.
     *
     * @throws NoSuchMethodException if the method is missing.
     */
    @Test
    void deleteByClientId_whenInspected_isTransactional() throws NoSuchMethodException {
        final var method = JdbcClientRegistrationRepository.class.getMethod("deleteByClientId", String.class);

        assertNotNull(method.getAnnotation(Transactional.class));
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
     * Saves a registration and captures the registered client handed to the registered client repository.
     *
     * @param registration the registration.
     * @param storedValue  encoded secret, or {@code null}.
     * @return the captured registered client.
     */
    private RegisteredClient save(final ClientRegistration registration, final String storedValue) {
        repository.save(registration, storedValue);
        final var captor = ArgumentCaptor.<RegisteredClient>captor();
        verify(registeredClientRepository).save(captor.capture());
        return captor.getValue();
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
     * Builds a confidential registration with refresh tokens and rotation.
     *
     * @return the registration.
     */
    private static ClientRegistration confidential() {
        return new ClientRegistration(CLIENT_ID, "Backend for Frontend", true, List.of("client_secret_basic"),
                List.of("authorization_code", "refresh_token"), List.of("http://localhost:8080/login/oauth2/code/bff"),
                List.of("openid", "profile"), true, List.of(AUDIENCE), ACCESS_TTL, REFRESH_TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false);
    }
}
