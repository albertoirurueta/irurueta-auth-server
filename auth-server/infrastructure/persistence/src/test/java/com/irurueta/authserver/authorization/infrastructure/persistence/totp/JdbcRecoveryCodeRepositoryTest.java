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

package com.irurueta.authserver.authorization.infrastructure.persistence.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcRecoveryCodeRepository}, with the JDBC client mocked. The statements themselves run
 * against PostgreSQL in {@link JdbcRecoveryCodeRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcRecoveryCodeRepositoryTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Statements run by replacing two codes: one delete and two inserts. */
    private static final int THREE_STATEMENTS = 3;

    /** Identifier of the user. */
    private final UUID userId = UUID.randomUUID();

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a row to a code; mocked so the tests control the mapped codes. */
    @Mock
    private RecoveryCodeRowMapper recoveryCodeRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcRecoveryCodeRepository repository;

    /**
     * Verifies that the previous codes are deleted and every new one is inserted.
     */
    @Test
    void replaceAll_whenCodesAreGiven_deletesThenInsertsEach() {
        final var first = new RecoveryCode(UUID.randomUUID(), userId, "hash-1", null);
        final var second = new RecoveryCode(UUID.randomUUID(), userId, "hash-2", NOW);

        final var spec = Mockito.mock(JdbcClient.StatementSpec.class, Answers.RETURNS_SELF);
        doReturn(spec).when(client).sql(any(String.class));

        repository.replaceAll(userId, List.of(first, second));

        verify(spec).param(userId);
        verify(spec).params(first.id(), userId, "hash-1", null);
        verify(spec).params(second.id(), userId, "hash-2", NOW.atOffset(ZoneOffset.UTC));
        verify(spec, times(THREE_STATEMENTS)).update();
    }

    /**
     * Verifies that the codes the query returns are passed through.
     */
    @Test
    void findUnused_whenRowsMatch_returnsMappedCodes() {
        final var code = new RecoveryCode(UUID.randomUUID(), userId, "hash", null);
        when(client.sql(any(String.class)).param(userId).query(recoveryCodeRowMapper).list())
                .thenReturn(List.of(code));

        assertEquals(List.of(code), repository.findUnused(userId));
    }

    /**
     * Verifies that {@code true} is returned when the conditional update spent a row.
     */
    @Test
    void markUsed_whenCodeIsUnused_returnsTrue() {
        final var id = UUID.randomUUID();
        when(client.sql(any(String.class)).params(NOW.atOffset(ZoneOffset.UTC), id).update()).thenReturn(1);

        assertTrue(repository.markUsed(id, NOW));
    }

    /**
     * Verifies that {@code false} is returned when the conditional update changed no row.
     */
    @Test
    void markUsed_whenCodeIsAlreadyUsed_returnsFalse() {
        final var id = UUID.randomUUID();
        when(client.sql(any(String.class)).params(NOW.atOffset(ZoneOffset.UTC), id).update()).thenReturn(0);

        assertFalse(repository.markUsed(id, NOW));
    }

    /**
     * Verifies that every code of the user is deleted.
     */
    @Test
    void deleteByUser_whenUserIsGiven_deletesTheRows() {
        repository.deleteByUser(userId);

        verify(client.sql(any(String.class)).param(userId)).update();
    }
}
