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

package com.irurueta.authserver.authorization.infrastructure.persistence.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.SecurityEvent;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcSecurityEventRepository}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcSecurityEventRepositoryTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Page size used by the tests. */
    private static final int LIMIT = 5;

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a row to an event; mocked so the tests control the mapped events. */
    @Mock
    private SecurityEventRowMapper securityEventRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcSecurityEventRepository repository;

    /**
     * Verifies that an event is inserted with its type name and UTC timestamp.
     */
    @Test
    void store_whenEventIsValid_insertsTheRow() {
        final var userId = UUID.randomUUID();
        final var event = new SecurityEvent(SecurityEventType.LOGIN_FAILURE, userId, "alice", "bad", NOW);

        repository.store(event);

        verify(client.sql(any(String.class)).params("LOGIN_FAILURE", userId, "alice", "bad",
                NOW.atOffset(ZoneOffset.UTC))).update();
    }

    /**
     * Verifies that the rows found are returned mapped.
     */
    @Test
    void findRecentByUser_whenRowsExist_returnsMappedEvents() {
        final var userId = UUID.randomUUID();
        final var events = List.of(new SecurityEvent(SecurityEventType.LOGIN_SUCCESS, userId, null, null, NOW));
        when(client.sql(any(String.class)).params(userId, LIMIT).query(securityEventRowMapper).list())
                .thenReturn(events);

        assertSame(events, repository.findRecentByUser(userId, LIMIT));
        assertEquals(1, events.size());
    }
}
