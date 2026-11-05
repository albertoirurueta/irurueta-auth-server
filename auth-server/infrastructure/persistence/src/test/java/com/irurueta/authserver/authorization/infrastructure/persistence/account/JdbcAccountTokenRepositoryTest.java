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

package com.irurueta.authserver.authorization.infrastructure.persistence.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.account.AccountToken;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcAccountTokenRepository}, with the JDBC client mocked. The statements themselves run
 * against PostgreSQL in {@link JdbcAccountTokenRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcAccountTokenRepositoryTest {

    /** Hash of the token used by the tests. */
    private static final String HASHED_TOKEN = "hashed-" + UUID.randomUUID();

    /** Purpose of the token used by the tests. */
    private static final String PURPOSE = AccountToken.PURPOSE_PASSWORD_RESET;

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Lifetime of the tokens used by the tests, in seconds. */
    private static final long TTL_SECONDS = 60;

    /** Number of rows the clean-up test reports as deleted. */
    private static final int DELETED = 3;

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Repository under test. */
    @InjectMocks
    private JdbcAccountTokenRepository repository;

    /**
     * Verifies that a token is stored with its timestamps converted to UTC.
     */
    @Test
    void store_whenTokenIsUnused_insertsTheRow() {
        final var token = new AccountToken(UUID.randomUUID(), UUID.randomUUID(), PURPOSE, HASHED_TOKEN,
                NOW.plusSeconds(TTL_SECONDS), null);

        repository.store(token);

        verify(client.sql(any(String.class)).params(token.id(), token.userId(), PURPOSE, HASHED_TOKEN,
                NOW.plusSeconds(TTL_SECONDS).atOffset(ZoneOffset.UTC), null)).update();
    }

    /**
     * Verifies that an empty result is returned when the statement matches no unused, unexpired token.
     */
    @Test
    void consume_whenNoRowMatches_returnsEmpty() {
        final var timestamp = NOW.atOffset(ZoneOffset.UTC);
        when(client.sql(any(String.class)).params(timestamp, HASHED_TOKEN, PURPOSE, timestamp)
                .query(ArgumentMatchers.<RowMapper<Object>>any()).optional())
                .thenReturn(Optional.empty());

        assertTrue(repository.consume(HASHED_TOKEN, PURPOSE, NOW).isEmpty());
    }

    /**
     * Verifies that the returned row is mapped to a token.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void consume_whenRowMatches_returnsMappedToken() throws SQLException {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();
        final var resultSet = mockRow(id, userId, NOW.atOffset(ZoneOffset.UTC));
        mockConsume(resultSet);

        final var token = repository.consume(HASHED_TOKEN, PURPOSE, NOW).orElseThrow();

        assertEquals(new AccountToken(id, userId, PURPOSE, HASHED_TOKEN, NOW.plusSeconds(TTL_SECONDS), NOW), token);
    }

    /**
     * Verifies that a row without a used-at instant is mapped to a token that was never used.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void consume_whenRowHasNoUsedAt_mapsNullUsedAt() throws SQLException {
        mockConsume(mockRow(UUID.randomUUID(), UUID.randomUUID(), null));

        assertNull(repository.consume(HASHED_TOKEN, PURPOSE, NOW).orElseThrow().usedAt());
    }

    /**
     * Verifies that the number of deleted rows is returned.
     */
    @Test
    void deleteExpired_whenRowsExpired_returnsDeletedCount() {
        when(client.sql(any(String.class)).param(NOW.atOffset(ZoneOffset.UTC)).update()).thenReturn(DELETED);

        assertEquals(DELETED, repository.deleteExpired(NOW));
    }

    /**
     * Makes the consume statement return the row mapped from a result set.
     *
     * @param resultSet result set the row mapper reads.
     * @throws SQLException never; declared by the mocked result set.
     */
    private void mockConsume(final ResultSet resultSet) throws SQLException {
        final var timestamp = NOW.atOffset(ZoneOffset.UTC);
        final var captor = ArgumentCaptor.<RowMapper<Object>>captor();
        when(client.sql(any(String.class)).params(timestamp, HASHED_TOKEN, PURPOSE, timestamp)
                .query(captor.capture()).optional())
                .thenAnswer(invocation -> Optional.of(captor.getValue().mapRow(resultSet, 0)));
    }

    /**
     * Mocks a result set row of the {@code account_tokens} table.
     *
     * @param id     identifier of the token.
     * @param userId identifier of the user.
     * @param usedAt instant the token was used, or {@code null}.
     * @return the mocked row.
     * @throws SQLException never; declared by the mocked result set.
     */
    private static ResultSet mockRow(final UUID id, final UUID userId, final OffsetDateTime usedAt)
            throws SQLException {
        final var resultSet = mock(ResultSet.class);
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getString("purpose")).thenReturn(PURPOSE);
        when(resultSet.getString("hashed_token")).thenReturn(HASHED_TOKEN);
        when(resultSet.getObject("expires_at", OffsetDateTime.class))
                .thenReturn(NOW.plusSeconds(TTL_SECONDS).atOffset(ZoneOffset.UTC));
        when(resultSet.getObject("used_at", OffsetDateTime.class)).thenReturn(usedAt);
        return resultSet;
    }
}
