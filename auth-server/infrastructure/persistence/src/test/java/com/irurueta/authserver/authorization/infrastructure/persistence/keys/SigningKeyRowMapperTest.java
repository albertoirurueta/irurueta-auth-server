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

package com.irurueta.authserver.authorization.infrastructure.persistence.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link SigningKeyRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class SigningKeyRowMapperTest {

    /** Key identifier used by the tests. */
    private static final String KID = "kid-1";

    /** Algorithm used by the tests. */
    private static final String ALG = "RS256";

    /** Public JWK used by the tests. */
    private static final String PUBLIC_JWK = "{\"kty\":\"RSA\"}";

    /** Encrypted private JWK used by the tests; not a real key. */
    private static final String ENCRYPTED_JWK = "encrypted-placeholder";

    /** Creation instant used by the tests. */
    private static final Instant CREATED = Instant.parse("2026-01-01T10:00:00Z");

    /** Activation instant used by the tests. */
    private static final Instant ACTIVATED = Instant.parse("2026-01-02T10:00:00Z");

    /** Retirement instant used by the tests. */
    private static final Instant RETIRED = Instant.parse("2026-01-03T10:00:00Z");

    /** Result set positioned on a row of {@code signing_keys}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final SigningKeyRowMapper mapper = new SigningKeyRowMapper();

    /**
     * Mocks the columns every test reads.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @BeforeEach
    void setUp() throws SQLException {
        when(resultSet.getString("kid")).thenReturn(KID);
        when(resultSet.getString("alg")).thenReturn(ALG);
        when(resultSet.getString("public_jwk")).thenReturn(PUBLIC_JWK);
        when(resultSet.getString("private_jwk_encrypted")).thenReturn(ENCRYPTED_JWK);
        when(resultSet.getObject("created_at", OffsetDateTime.class)).thenReturn(CREATED.atOffset(ZoneOffset.UTC));
    }

    /**
     * Verifies that a key that was never activated is mapped with null activation and retirement.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenKeyIsNext_mapsNullActivationAndRetirement() throws SQLException {
        when(resultSet.getString("status")).thenReturn("NEXT");
        when(resultSet.getObject("activated_at", OffsetDateTime.class)).thenReturn(null);
        when(resultSet.getObject("retired_at", OffsetDateTime.class)).thenReturn(null);

        assertEquals(new SigningKey(KID, ALG, PUBLIC_JWK, ENCRYPTED_JWK, SigningKeyStatus.NEXT, CREATED, null, null),
                mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that a retired key is mapped with every timestamp.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenKeyIsRetired_mapsEveryTimestamp() throws SQLException {
        when(resultSet.getString("status")).thenReturn("RETIRED");
        when(resultSet.getObject("activated_at", OffsetDateTime.class))
                .thenReturn(ACTIVATED.atOffset(ZoneOffset.UTC));
        when(resultSet.getObject("retired_at", OffsetDateTime.class)).thenReturn(RETIRED.atOffset(ZoneOffset.UTC));

        assertEquals(new SigningKey(KID, ALG, PUBLIC_JWK, ENCRYPTED_JWK, SigningKeyStatus.RETIRED, CREATED,
                ACTIVATED, RETIRED), mapper.mapRow(resultSet, 0));
    }
}
