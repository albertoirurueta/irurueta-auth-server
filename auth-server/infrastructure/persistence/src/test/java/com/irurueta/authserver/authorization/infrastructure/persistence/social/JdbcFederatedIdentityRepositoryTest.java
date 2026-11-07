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
package com.irurueta.authserver.authorization.infrastructure.persistence.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcFederatedIdentityRepository}, with the JDBC client mocked. The statements themselves run
 * against PostgreSQL in {@link JdbcFederatedIdentityRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcFederatedIdentityRepositoryTest {

    /** Subject used by the tests. */
    private static final String SUBJECT = "subject-1";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Instant the identity was linked. */
    private static final Instant LINKED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Number of identities the count test reports. */
    private static final long COUNT = 3;

    /** Identifier of the link. */
    private final UUID id = UUID.randomUUID();

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a row to an identity; mocked so the tests control the mapped identities. */
    @Mock
    private FederatedIdentityRowMapper federatedIdentityRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcFederatedIdentityRepository repository;

    /**
     * Verifies that the identity the query returns is mapped with the row mapper.
     */
    @Test
    void findByProviderAndSubject_whenRowMatches_returnsMappedIdentity() {
        final var identity = identity();
        when(client.sql(any(String.class)).params("google", SUBJECT).query(federatedIdentityRowMapper).optional())
                .thenReturn(Optional.of(identity));

        assertSame(identity, repository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT).orElseThrow());
    }

    /**
     * Verifies that the identities of the account are listed through the row mapper.
     */
    @Test
    void findByUser_whenAccountHasIdentities_returnsMappedIdentities() {
        final var identities = List.of(identity());
        when(client.sql(any(String.class)).param(userId).query(federatedIdentityRowMapper).list())
                .thenReturn(identities);

        assertEquals(identities, repository.findByUser(userId));
    }

    /**
     * Verifies that one identity of the account is found through the row mapper.
     */
    @Test
    void findByIdAndUser_whenRowMatches_returnsMappedIdentity() {
        final var identity = identity();
        when(client.sql(any(String.class)).params(id, userId).query(federatedIdentityRowMapper).optional())
                .thenReturn(Optional.of(identity));

        assertSame(identity, repository.findByIdAndUser(id, userId).orElseThrow());
    }

    /**
     * Verifies that an identity is stored with its timestamps converted to UTC and returned unchanged.
     */
    @Test
    void save_whenIdentityIsValid_upsertsTheRowAndReturnsIt() {
        final var identity = identity();

        assertSame(identity, repository.save(identity));

        verify(client.sql(any(String.class)).params(id, userId, "google", SUBJECT, EMAIL,
                LINKED_AT.atOffset(ZoneOffset.UTC), null)).update();
    }

    /**
     * Verifies that deleting reports {@code true} when a row was deleted and {@code false} otherwise.
     */
    @Test
    void delete_whenRowDeletedOrNot_reportsIt() {
        when(client.sql(any(String.class)).params(id, userId).update()).thenReturn(1, 0);

        assertTrue(repository.delete(id, userId));
        assertFalse(repository.delete(id, userId));
    }

    /**
     * Verifies that the number of identities is returned.
     */
    @Test
    void countByUser_whenAccountHasIdentities_returnsTheCount() {
        when(client.sql(any(String.class)).param(userId).query(Long.class).single()).thenReturn(COUNT);

        assertEquals(COUNT, repository.countByUser(userId));
    }

    /**
     * Builds the identity used by the tests.
     *
     * @return the identity.
     */
    private FederatedIdentity identity() {
        return new FederatedIdentity(id, userId, IdentityProvider.GOOGLE, SUBJECT, EMAIL, LINKED_AT, null);
    }
}
