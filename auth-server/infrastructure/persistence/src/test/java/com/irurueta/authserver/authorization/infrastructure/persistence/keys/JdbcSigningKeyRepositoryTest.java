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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Unit tests of {@link JdbcSigningKeyRepository}, with the JDBC client and the transaction template mocked. The
 * statements and the lock run against PostgreSQL in {@link JdbcSigningKeyRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcSigningKeyRepositoryTest {

    /** Key identifier used by the tests. */
    private static final String KID = "kid-1";

    /** Algorithm used by the tests. */
    private static final String ALG = "RS256";

    /** Public JWK used by the tests. */
    private static final String PUBLIC_JWK = "{\"kty\":\"RSA\"}";

    /** Encrypted private JWK used by the tests; not a real key. */
    private static final String ENCRYPTED_JWK = "encrypted-placeholder";

    /** Creation instant used by the tests. */
    private static final Instant CREATED = Instant.parse("2026-01-01T10:00:00Z");

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Template that runs the rotation in a transaction. */
    @Mock
    private TransactionTemplate transactionTemplate;

    /** Maps a row to a key; mocked so the tests control the mapped keys. */
    @Mock
    private SigningKeyRowMapper signingKeyRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcSigningKeyRepository repository;

    /**
     * Verifies that the rows are read with the signing key row mapper and returned as they are mapped.
     */
    @Test
    void findAll_whenRowsExist_returnsMappedKeys() {
        final var key = new SigningKey(KID, ALG, PUBLIC_JWK, ENCRYPTED_JWK, SigningKeyStatus.NEXT, CREATED, null,
                null);
        when(client.sql(any(String.class)).query(signingKeyRowMapper).list()).thenReturn(List.of(key));

        final var keys = repository.findAll();

        assertEquals(List.of(key), keys);
    }

    /**
     * Verifies that a key is written with its status name and UTC timestamps.
     */
    @Test
    void save_whenKeyIsActive_upsertsTheRow() {
        final var key = new SigningKey(KID, ALG, PUBLIC_JWK, ENCRYPTED_JWK, SigningKeyStatus.ACTIVE, CREATED,
                CREATED, null);

        repository.save(key);

        verify(client.sql(any(String.class)).params(KID, ALG, PUBLIC_JWK, ENCRYPTED_JWK, "ACTIVE",
                CREATED.atOffset(ZoneOffset.UTC), CREATED.atOffset(ZoneOffset.UTC), null)).update();
    }

    /**
     * Verifies that the key is deleted by its identifier.
     */
    @Test
    void deleteByKid_whenCalled_deletesTheRow() {
        repository.deleteByKid(KID);

        verify(client.sql(any(String.class)).param(KID)).update();
    }

    /**
     * Verifies that the lock is taken with the advisory lock key before the action runs, and that the action's
     * result is returned.
     */
    @Test
    void withRotationLock_whenCalled_locksAndReturnsTheResult() {
        final var result = new Object();
        when(transactionTemplate.execute(any())).thenAnswer(invocation -> invocation
                .<TransactionCallback<Object>>getArgument(0).doInTransaction(mock(TransactionStatus.class)));

        final var actual = repository.withRotationLock(() -> result);

        assertSame(result, actual);
        verify(client.sql(any(String.class)).param(JdbcSigningKeyRepository.ROTATION_LOCK_KEY))
                .query(ArgumentMatchers.<RowMapper<Object>>any());
    }

    /**
     * Verifies that a null result of the action is returned unchanged.
     */
    @Test
    void withRotationLock_whenActionReturnsNull_returnsNull() {
        when(transactionTemplate.execute(any())).thenAnswer(invocation -> invocation
                .<TransactionCallback<Object>>getArgument(0).doInTransaction(mock(TransactionStatus.class)));

        assertNull(repository.withRotationLock(() -> null));
    }
}
