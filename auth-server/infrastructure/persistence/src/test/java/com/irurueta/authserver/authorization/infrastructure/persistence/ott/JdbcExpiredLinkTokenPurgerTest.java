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

package com.irurueta.authserver.authorization.infrastructure.persistence.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * Unit tests of {@link JdbcExpiredLinkTokenPurger}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcExpiredLinkTokenPurgerTest {

    /** Number of rows the statement reports deleted. */
    private static final int DELETED = 3;

    /** Mocked client with a fluent statement. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient jdbcClient;

    /** Subject under test. */
    @InjectMocks
    private JdbcExpiredLinkTokenPurger purger;

    /**
     * Checks that the number of deleted rows is returned.
     */
    @Test
    void deleteExpired_whenRowsExpired_returnsDeletedCount() {
        when(jdbcClient.sql(org.mockito.ArgumentMatchers.anyString())
                .param(org.mockito.ArgumentMatchers.any()).update()).thenReturn(DELETED);

        assertEquals(DELETED, purger.deleteExpired(Instant.EPOCH));

        verify(jdbcClient).sql("DELETE FROM one_time_tokens WHERE expires_at <= ?");
    }
}
