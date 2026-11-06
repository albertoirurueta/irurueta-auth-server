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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
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
 * Unit tests of {@link JdbcTrustedDeviceRepository}, with the JDBC client mocked. The statements themselves run
 * against PostgreSQL in {@link JdbcTrustedDeviceRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcTrustedDeviceRepositoryTest {

    /** Hash of the token used by the tests. */
    private static final String HASHED_TOKEN = "hashed-" + UUID.randomUUID();

    /** User agent summary used by the tests. */
    private static final String USER_AGENT = "Firefox on Linux";

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Lifetime of the devices used by the tests, in seconds. */
    private static final long TTL_SECONDS = 60;

    /** Number of rows the clean-up test reports as deleted. */
    private static final int DELETED = 3;

    /** Identifier of the user used by the tests. */
    private final UUID userId = UUID.randomUUID();

    /** Identifier of the device used by the tests. */
    private final UUID deviceId = UUID.randomUUID();

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a row to a device; mocked so the tests control the mapped devices. */
    @Mock
    private TrustedDeviceRowMapper trustedDeviceRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcTrustedDeviceRepository repository;

    /**
     * Verifies that a device is stored with its timestamps converted to UTC.
     */
    @Test
    void store_whenDeviceIsValid_insertsTheRow() {
        final var device = device();

        repository.store(device);

        verify(client.sql(any(String.class)).params(deviceId, userId, HASHED_TOKEN, USER_AGENT,
                NOW.plusSeconds(TTL_SECONDS).atOffset(ZoneOffset.UTC), NOW.atOffset(ZoneOffset.UTC))).update();
    }

    /**
     * Verifies that the unexpired device the query returns is mapped with the row mapper.
     */
    @Test
    void findUsable_whenRowMatches_returnsMappedDevice() {
        final var device = device();
        when(client.sql(any(String.class)).params(userId, HASHED_TOKEN, NOW.atOffset(ZoneOffset.UTC))
                .query(trustedDeviceRowMapper).optional())
                .thenReturn(Optional.of(device));

        assertSame(device, repository.findUsable(userId, HASHED_TOKEN, NOW).orElseThrow());
    }

    /**
     * Verifies that an empty result is returned when no unexpired device matches.
     */
    @Test
    void findUsable_whenNoRowMatches_returnsEmpty() {
        when(client.sql(any(String.class)).params(userId, HASHED_TOKEN, NOW.atOffset(ZoneOffset.UTC))
                .query(trustedDeviceRowMapper).optional())
                .thenReturn(Optional.empty());

        assertTrue(repository.findUsable(userId, HASHED_TOKEN, NOW).isEmpty());
    }

    /**
     * Verifies that the devices of the user are listed through the row mapper.
     */
    @Test
    void findByUser_whenUserHasDevices_returnsMappedDevices() {
        final var devices = List.of(device());
        when(client.sql(any(String.class)).params(userId, NOW.atOffset(ZoneOffset.UTC))
                .query(trustedDeviceRowMapper).list())
                .thenReturn(devices);

        assertEquals(devices, repository.findByUser(userId, NOW));
    }

    /**
     * Verifies that revoking reports {@code true} when a row was deleted.
     */
    @Test
    void revoke_whenRowDeleted_returnsTrue() {
        when(client.sql(any(String.class)).params(userId, deviceId).update()).thenReturn(1);

        assertTrue(repository.revoke(userId, deviceId));
    }

    /**
     * Verifies that revoking reports {@code false} when no row matched.
     */
    @Test
    void revoke_whenNoRowDeleted_returnsFalse() {
        when(client.sql(any(String.class)).params(userId, deviceId).update()).thenReturn(0);

        assertFalse(repository.revoke(userId, deviceId));
    }

    /**
     * Verifies that every device of a user is deleted and their number returned.
     */
    @Test
    void deleteByUser_whenUserHasDevices_returnsDeletedCount() {
        when(client.sql(any(String.class)).param(userId).update()).thenReturn(DELETED);

        assertEquals(DELETED, repository.deleteByUser(userId));
    }

    /**
     * Verifies that the number of deleted rows is returned.
     */
    @Test
    void deleteExpired_whenRowsExpired_returnsDeletedCount() {
        when(client.sql(any(String.class)).param(NOW.atOffset(ZoneOffset.UTC)).update()).thenReturn(DELETED);

        assertEquals(DELETED, repository.deleteExpired(NOW));
    }

    /**
     * Builds the device used by the tests.
     *
     * @return the device.
     */
    private TrustedDevice device() {
        return new TrustedDevice(deviceId, userId, HASHED_TOKEN, USER_AGENT, NOW.plusSeconds(TTL_SECONDS), NOW);
    }
}
