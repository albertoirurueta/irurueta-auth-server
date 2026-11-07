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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcGeneratedPasswordRepository}, with the JDBC client mocked. The statements themselves run
 * against PostgreSQL in {@link JdbcGeneratedPasswordRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcGeneratedPasswordRepositoryTest {

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Repository under test. */
    @InjectMocks
    private JdbcGeneratedPasswordRepository repository;

    /**
     * Verifies that the flag is set with an update of the account's password row.
     */
    @Test
    void markGenerated_whenCalled_updatesTheRow() {
        repository.markGenerated(userId);

        verify(client.sql(any(String.class)).param(userId)).update();
    }

    /**
     * Verifies that a generated password is reported when the count is positive.
     */
    @Test
    void isGenerated_whenRowIsFlagged_returnsTrueOtherwiseFalse() {
        when(client.sql(any(String.class)).param(userId).query(Long.class).single()).thenReturn(1L, 0L);

        assertTrue(repository.isGenerated(userId));
        assertFalse(repository.isGenerated(userId));
    }
}
