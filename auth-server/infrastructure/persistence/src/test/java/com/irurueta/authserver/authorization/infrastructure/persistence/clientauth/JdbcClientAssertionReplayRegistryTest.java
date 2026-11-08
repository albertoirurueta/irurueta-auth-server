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

package com.irurueta.authserver.authorization.infrastructure.persistence.clientauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcClientAssertionReplayRegistry}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcClientAssertionReplayRegistryTest {

    /** Rows a purge reports deleted. */
    private static final int DELETED = 3;

    /** Mocked client with a fluent statement. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient jdbcClient;

    /** Subject under test. */
    @InjectMocks
    private JdbcClientAssertionReplayRegistry registry;

    /**
     * Verifies that an inserted row is a first use.
     */
    @Test
    void register_whenRowInserted_returnsTrue() {
        when(jdbcClient.sql(anyString()).params(any(Object[].class)).update()).thenReturn(1);

        assertTrue(registry.register("client", "jti", Instant.EPOCH));

        verify(jdbcClient).sql("INSERT INTO client_assertion_jtis (client_id, jti, expires_at) "
                + "VALUES (?, ?, ?) ON CONFLICT (client_id, jti) DO NOTHING");
    }

    /**
     * Verifies that a conflicting insert, which affects no row, is a replay.
     */
    @Test
    void register_whenNoRowInserted_returnsFalse() {
        when(jdbcClient.sql(anyString()).params(any(Object[].class)).update()).thenReturn(0);

        assertFalse(registry.register("client", "jti", Instant.EPOCH));
    }

    /**
     * Verifies that the number of deleted rows is returned.
     */
    @Test
    void purgeExpired_whenRowsExpired_returnsDeletedCount() {
        when(jdbcClient.sql(anyString()).param(any()).update()).thenReturn(DELETED);

        assertEquals(DELETED, registry.purgeExpired(Instant.EPOCH));

        verify(jdbcClient).sql("DELETE FROM client_assertion_jtis WHERE expires_at <= ?");
    }
}
