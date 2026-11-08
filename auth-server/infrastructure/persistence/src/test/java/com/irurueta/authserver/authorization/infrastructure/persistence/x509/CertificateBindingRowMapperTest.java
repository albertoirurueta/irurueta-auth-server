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
package com.irurueta.authserver.authorization.infrastructure.persistence.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
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
 * Unit tests of {@link CertificateBindingRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class CertificateBindingRowMapperTest {

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "d".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** Subject used by the tests. */
    private static final String SUBJECT = "CN=alice";

    /** Instant the certificate was bound. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Result set positioned on a row of {@code x509_certificates}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final CertificateBindingRowMapper mapper = new CertificateBindingRowMapper();

    /**
     * Verifies that a row is mapped completely.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenRowIsValid_mapsEveryColumn() throws SQLException {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getString("fingerprint_sha256")).thenReturn(FINGERPRINT);
        when(resultSet.getString("subject_dn")).thenReturn(SUBJECT);
        when(resultSet.getObject("created_at", OffsetDateTime.class)).thenReturn(CREATED_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new CertificateBinding(id, userId, FINGERPRINT, SUBJECT, CREATED_AT),
                mapper.mapRow(resultSet, 0));
    }
}
