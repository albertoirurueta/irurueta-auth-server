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

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockout;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
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
 * Unit tests of {@link JdbcSecondFactorAttemptRepository}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcSecondFactorAttemptRepositoryTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Maximum attempts used by the tests. */
    private static final int MAX_ATTEMPTS = 5;

    /** Lock duration used by the tests. */
    private static final Duration LOCKOUT = Duration.ofMinutes(15);

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a row to a state; mocked so the tests control the mapped states. */
    @Mock
    private SecondFactorLockoutRowMapper secondFactorLockoutRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcSecondFactorAttemptRepository repository;

    /**
     * Verifies that the stored state is returned when a row exists.
     */
    @Test
    void find_whenRowExists_returnsMappedState() {
        final var userId = UUID.randomUUID();
        final var state = new SecondFactorLockout(2, null);
        when(client.sql(any(String.class)).param(userId).query(secondFactorLockoutRowMapper).optional())
                .thenReturn(Optional.of(state));

        assertSame(state, repository.find(userId));
    }

    /**
     * Verifies that a clean state is returned when nothing was recorded.
     */
    @Test
    void find_whenNoRow_returnsNone() {
        final var userId = UUID.randomUUID();
        when(client.sql(any(String.class)).param(userId).query(secondFactorLockoutRowMapper).optional())
                .thenReturn(Optional.empty());

        assertEquals(SecondFactorLockout.none(), repository.find(userId));
    }

    /**
     * Verifies that a failure is recorded with one statement binding the lock end as now plus the lock duration.
     */
    @Test
    void recordFailure_whenCalled_returnsStateOfTheUpsert() {
        final var userId = UUID.randomUUID();
        final var state = new SecondFactorLockout(1, null);
        final var params = Map.<String, Object>of("userId", userId, "maxAttempts", MAX_ATTEMPTS,
                "now", NOW.atOffset(ZoneOffset.UTC), "lockedUntil", NOW.plus(LOCKOUT).atOffset(ZoneOffset.UTC));
        when(client.sql(any(String.class)).params(params).query(secondFactorLockoutRowMapper).single())
                .thenReturn(state);

        assertSame(state, repository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, NOW));
    }

    /**
     * Verifies that the state of a user is deleted on reset.
     */
    @Test
    void reset_whenCalled_deletesTheRow() {
        final var userId = UUID.randomUUID();

        repository.reset(userId);

        verify(client.sql(any(String.class)).param(userId)).update();
    }
}
