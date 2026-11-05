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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.account.AccountToken;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
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

    /** Maps a row to a token; mocked so the tests control the mapped tokens. */
    @Mock
    private AccountTokenRowMapper accountTokenRowMapper;

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
     * Verifies that the row the statement returns is mapped with the account token row mapper, binding the current
     * instant both as the used-at value and as the expiry bound.
     */
    @Test
    void consume_whenRowMatches_returnsMappedToken() {
        final var token = new AccountToken(UUID.randomUUID(), UUID.randomUUID(), PURPOSE, HASHED_TOKEN,
                NOW.plusSeconds(TTL_SECONDS), NOW);
        final var timestamp = NOW.atOffset(ZoneOffset.UTC);
        when(client.sql(any(String.class)).params(timestamp, HASHED_TOKEN, PURPOSE, timestamp)
                .query(accountTokenRowMapper).optional())
                .thenReturn(Optional.of(token));

        assertSame(token, repository.consume(HASHED_TOKEN, PURPOSE, NOW).orElseThrow());
    }

    /**
     * Verifies that the look-up maps the usable row it finds with the account token row mapper, without consuming
     * it.
     */
    @Test
    void findUsable_whenRowMatches_returnsMappedToken() {
        final var token = new AccountToken(UUID.randomUUID(), UUID.randomUUID(), PURPOSE, HASHED_TOKEN,
                NOW.plusSeconds(TTL_SECONDS), null);
        when(client.sql(any(String.class)).params(HASHED_TOKEN, PURPOSE, NOW.atOffset(ZoneOffset.UTC))
                .query(accountTokenRowMapper).optional())
                .thenReturn(Optional.of(token));

        assertSame(token, repository.findUsable(HASHED_TOKEN, PURPOSE, NOW).orElseThrow());
    }

    /**
     * Verifies that the number of deleted rows is returned.
     */
    @Test
    void deleteExpired_whenRowsExpired_returnsDeletedCount() {
        when(client.sql(any(String.class)).param(NOW.atOffset(ZoneOffset.UTC)).update()).thenReturn(DELETED);

        assertEquals(DELETED, repository.deleteExpired(NOW));
    }
}
