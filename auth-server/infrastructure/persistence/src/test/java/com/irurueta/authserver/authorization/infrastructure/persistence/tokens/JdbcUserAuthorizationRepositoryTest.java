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

package com.irurueta.authserver.authorization.infrastructure.persistence.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.sql.Timestamp;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcUserAuthorizationRepository}, with the JDBC client mocked. The statements run against
 * PostgreSQL in {@link JdbcUserAuthorizationRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcUserAuthorizationRepositoryTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Number of rows reported as deleted. */
    private static final int DELETED = 4;

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Repository under test. */
    @InjectMocks
    private JdbcUserAuthorizationRepository repository;

    /**
     * Verifies that the number of authorizations deleted for the principal is returned.
     */
    @Test
    void deleteByPrincipalName_whenCalled_returnsDeletedCount() {
        when(client.sql(any(String.class)).param("alice").update()).thenReturn(DELETED);

        assertEquals(DELETED, repository.deleteByPrincipalName("alice"));
    }

    /**
     * Verifies that the number of expired authorizations deleted is returned.
     */
    @Test
    void deleteExpired_whenCalled_returnsDeletedCount() {
        when(client.sql(any(String.class)).param(Timestamp.from(NOW)).update()).thenReturn(DELETED);

        assertEquals(DELETED, repository.deleteExpired(NOW));
    }
}
