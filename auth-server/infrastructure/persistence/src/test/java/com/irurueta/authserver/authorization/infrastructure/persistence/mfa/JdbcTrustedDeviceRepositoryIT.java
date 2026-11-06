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
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcTrustedDeviceRepository} against PostgreSQL. No Spring context is needed.
 */
class JdbcTrustedDeviceRepositoryIT {

    /** Lifetime of the devices, in seconds. */
    private static final long TTL_SECONDS = 60;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcTrustedDeviceRepository repository;

    /** Identifier of the user that owns the devices. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcTrustedDeviceRepository(jdbcClient, new TrustedDeviceRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts the user that owns the devices.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(userId, "user-" + userId).update();
    }

    /**
     * Verifies that a stored device is found by its hash, with every field round-tripped.
     */
    @Test
    void findUsable_whenDeviceIsUnexpired_returnsIt() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var device = device(hash(), now.plusSeconds(TTL_SECONDS), now);
        repository.store(device);

        assertEquals(device, repository.findUsable(userId, device.hashedToken(), now).orElseThrow());
    }

    /**
     * Verifies that an expired device, or one of another user, is not found.
     */
    @Test
    void findUsable_whenDeviceIsExpiredOrOfAnotherUser_returnsEmpty() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var expired = device(hash(), now.minusSeconds(1), now.minusSeconds(TTL_SECONDS));
        final var valid = device(hash(), now.plusSeconds(TTL_SECONDS), now);
        repository.store(expired);
        repository.store(valid);

        assertTrue(repository.findUsable(userId, expired.hashedToken(), now).isEmpty());
        assertTrue(repository.findUsable(UUID.randomUUID(), valid.hashedToken(), now).isEmpty());
    }

    /**
     * Verifies that only the unexpired devices of the user are listed.
     */
    @Test
    void findByUser_whenSomeDevicesExpired_listsOnlyUnexpired() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        repository.store(device(hash(), now.minusSeconds(1), now.minusSeconds(TTL_SECONDS)));
        final var valid = device(hash(), now.plusSeconds(TTL_SECONDS), now);
        repository.store(valid);

        assertEquals(List.of(valid), repository.findByUser(userId, now));
    }

    /**
     * Verifies that a device is revoked only by its owner.
     */
    @Test
    void revoke_whenUserIsOwner_deletesOnlyForOwner() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var device = device(hash(), now.plusSeconds(TTL_SECONDS), now);
        repository.store(device);

        assertFalse(repository.revoke(UUID.randomUUID(), device.id()));
        assertTrue(repository.revoke(userId, device.id()));
        assertTrue(repository.findUsable(userId, device.hashedToken(), now).isEmpty());
    }

    /**
     * Verifies that every device of the user is deleted, and the devices of another user are kept.
     */
    @Test
    void deleteByUser_whenTwoUsersHaveDevices_deletesOnlyTheUsers() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var otherId = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(otherId, "user-" + otherId).update();
        repository.store(device(hash(), now.plusSeconds(TTL_SECONDS), now));
        repository.store(device(hash(), now.minusSeconds(1), now.minusSeconds(TTL_SECONDS)));
        final var other = new TrustedDevice(UUID.randomUUID(), otherId, hash(), null, now.plusSeconds(TTL_SECONDS),
                now);
        repository.store(other);

        assertEquals(2, repository.deleteByUser(userId));
        assertTrue(repository.findByUser(userId, now).isEmpty());
        assertEquals(List.of(other), repository.findByUser(otherId, now));
    }

    /**
     * Verifies that only the expired devices are deleted.
     */
    @Test
    void deleteExpired_whenSomeDevicesExpired_deletesOnlyThose() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        repository.store(device(hash(), now.minusSeconds(1), now.minusSeconds(TTL_SECONDS)));
        repository.store(device(hash(), now.plusSeconds(TTL_SECONDS), now));

        assertEquals(1, repository.deleteExpired(now));
    }

    /**
     * Builds a device of the user.
     *
     * @param hash      hash of the device token.
     * @param expiresAt expiry instant.
     * @param createdAt creation instant.
     * @return the device.
     */
    private TrustedDevice device(final String hash, final Instant expiresAt, final Instant createdAt) {
        return new TrustedDevice(UUID.randomUUID(), userId, hash, "Firefox on Linux", expiresAt, createdAt);
    }

    /**
     * Generates a random token hash.
     *
     * @return the hash placeholder.
     */
    private static String hash() {
        return "hash-" + UUID.randomUUID();
    }
}
