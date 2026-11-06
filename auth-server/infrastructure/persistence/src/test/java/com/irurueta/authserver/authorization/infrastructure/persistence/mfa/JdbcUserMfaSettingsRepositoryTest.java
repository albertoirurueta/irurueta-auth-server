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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
 * Unit tests of {@link JdbcUserMfaSettingsRepository}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcUserMfaSettingsRepositoryTest {

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Repository under test. */
    @InjectMocks
    private JdbcUserMfaSettingsRepository repository;

    /**
     * Verifies that the stored flag is returned.
     */
    @Test
    void isRequired_whenFlagIsTrue_returnsTrue() {
        final var userId = UUID.randomUUID();
        when(client.sql(any(String.class)).param(userId).query(Boolean.class).optional())
                .thenReturn(Optional.of(true));

        assertTrue(repository.isRequired(userId));
    }

    /**
     * Verifies that a missing user does not require a second factor.
     */
    @Test
    void isRequired_whenUserIsMissing_returnsFalse() {
        final var userId = UUID.randomUUID();
        when(client.sql(any(String.class)).param(userId).query(Boolean.class).optional())
                .thenReturn(Optional.empty());

        assertFalse(repository.isRequired(userId));
    }

    /**
     * Verifies that the flag is updated.
     */
    @Test
    void setRequired_whenCalled_updatesTheRow() {
        final var userId = UUID.randomUUID();

        repository.setRequired(userId, true);

        verify(client.sql(any(String.class)).params(true, userId)).update();
    }
}
