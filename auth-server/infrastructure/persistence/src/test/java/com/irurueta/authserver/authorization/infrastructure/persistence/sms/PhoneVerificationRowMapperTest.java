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

package com.irurueta.authserver.authorization.infrastructure.persistence.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerification;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link PhoneVerificationRowMapper}.
 */
@ExtendWith(MockitoExtension.class)
class PhoneVerificationRowMapperTest {

    /** Pending phone number of the row. */
    private static final String PHONE = "+34600000002";

    /** Number of failed attempts. */
    private static final int ATTEMPTS = 3;

    /** Instant the verification expires. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-01T10:10:00Z");

    /** Identifier of the user. */
    private final UUID userId = UUID.randomUUID();

    /** Result set positioned on a row of {@code user_phones}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final PhoneVerificationRowMapper mapper = new PhoneVerificationRowMapper();

    /**
     * Verifies that the pending columns are mapped.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenVerificationIsPending_mapsPendingColumns() throws SQLException {
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getString("pending_phone_e164")).thenReturn(PHONE);
        when(resultSet.getString("pending_code_hash")).thenReturn("hash");
        when(resultSet.getInt("pending_attempts")).thenReturn(ATTEMPTS);
        when(resultSet.getObject("pending_expires_at", OffsetDateTime.class))
                .thenReturn(EXPIRES_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new PhoneVerification(userId, new PhoneNumber(PHONE), "hash", ATTEMPTS, EXPIRES_AT),
                mapper.mapRow(resultSet, 0));
    }
}
