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
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockout;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link SecondFactorLockoutRowMapper}.
 */
@ExtendWith(MockitoExtension.class)
class SecondFactorLockoutRowMapperTest {

    /** Number of failures used by the tests. */
    private static final int FAILED = 3;

    /** End of the lock used by the tests. */
    private static final Instant LOCKED_UNTIL = Instant.parse("2026-01-01T10:15:00Z");

    /** Result set positioned on a row of {@code second_factor_attempts}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final SecondFactorLockoutRowMapper mapper = new SecondFactorLockoutRowMapper();

    /**
     * Verifies that a locked row is mapped with its lock end.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenLocked_mapsLockedUntil() throws SQLException {
        when(resultSet.getInt("failed_count")).thenReturn(FAILED);
        when(resultSet.getObject("locked_until", OffsetDateTime.class))
                .thenReturn(LOCKED_UNTIL.atOffset(ZoneOffset.UTC));

        assertEquals(new SecondFactorLockout(FAILED, LOCKED_UNTIL), mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that a row without a lock is mapped with a null lock end.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenNotLocked_mapsNullLockedUntil() throws SQLException {
        when(resultSet.getInt("failed_count")).thenReturn(1);

        assertEquals(new SecondFactorLockout(1, null), mapper.mapRow(resultSet, 0));
    }
}
