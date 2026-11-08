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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link DeviceVerificationRateLimiter}, with a mocked clock.
 */
@ExtendWith(MockitoExtension.class)
class DeviceVerificationRateLimiterTest {

    /** Start of the first window. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Length of a window. */
    private static final Duration WINDOW = Duration.ofMinutes(15);

    /** Attempts one client address may make in a window. */
    private static final int PER_CLIENT = 3;

    /** Attempts one user may make in a window. */
    private static final int PER_USER = 2;

    /** Keys tracked at most per kind. */
    private static final int MAX_KEYS = 10;

    /** A client address. */
    private static final String CLIENT = "192.0.2.1";

    /** Another client address. */
    private static final String OTHER_CLIENT = "192.0.2.2";

    /** A user. */
    private static final String USER = "alice";

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /**
     * Verifies that a client address over its limit is told how long to wait, whoever the users are.
     */
    @Test
    void check_whenClientExceedsItsLimit_throwsWithTheRestOfTheWindow() {
        when(clock.instant()).thenReturn(NOW);
        final var limiter = limiter(true, PER_CLIENT);
        for (var attempt = 0; attempt < PER_CLIENT; attempt++) {
            final var user = "user-" + attempt;
            assertDoesNotThrow(() -> limiter.check(CLIENT, user));
        }

        final var error = assertThrows(DeviceVerificationRateLimitedException.class,
                () -> limiter.check(CLIENT, "another"));

        assertEquals(WINDOW, error.retryAfter());
        assertDoesNotThrow(() -> limiter.check(OTHER_CLIENT, "another"));
    }

    /**
     * Verifies that a user over its limit is refused whatever the client address is.
     */
    @Test
    void check_whenUserExceedsItsLimit_throws() {
        when(clock.instant()).thenReturn(NOW);
        final var limiter = limiter(true, PER_CLIENT);
        assertDoesNotThrow(() -> limiter.check(CLIENT, USER));
        assertDoesNotThrow(() -> limiter.check(OTHER_CLIENT, USER));

        assertThrows(DeviceVerificationRateLimitedException.class, () -> limiter.check("192.0.2.3", USER));
    }

    /**
     * Verifies that an unknown client address is counted as one client.
     */
    @Test
    void check_whenClientAddressIsUnknown_countsThemTogether() {
        when(clock.instant()).thenReturn(NOW);
        final var limiter = limiter(true, 1);
        assertDoesNotThrow(() -> limiter.check(null, "first"));

        assertThrows(DeviceVerificationRateLimitedException.class, () -> limiter.check(null, "second"));
    }

    /**
     * Verifies that nothing is limited when the limiter is disabled.
     */
    @Test
    void check_whenDisabled_neverThrows() {
        final var limiter = limiter(false, 1);

        for (var attempt = 0; attempt < PER_CLIENT * 2; attempt++) {
            assertDoesNotThrow(() -> limiter.check(CLIENT, USER));
        }
    }

    /**
     * Verifies that the attempts are accepted again when the window ends.
     */
    @Test
    void check_whenTheWindowEnds_acceptsAttemptsAgain() {
        when(clock.instant()).thenReturn(NOW);
        final var limiter = limiter(true, 1);
        assertDoesNotThrow(() -> limiter.check(CLIENT, USER));
        assertThrows(DeviceVerificationRateLimitedException.class, () -> limiter.check(CLIENT, USER));

        when(clock.instant()).thenReturn(NOW.plus(WINDOW).plusSeconds(1));

        assertDoesNotThrow(() -> limiter.check(CLIENT, USER));
    }

    /**
     * Builds the limiter.
     *
     * @param enabled   whether attempts are limited.
     * @param perClient attempts per client address.
     * @return the limiter.
     */
    private DeviceVerificationRateLimiter limiter(final boolean enabled, final int perClient) {
        return new DeviceVerificationRateLimiter(
                new DeviceRateLimitProperties(enabled, WINDOW, perClient, PER_USER, MAX_KEYS), clock);
    }
}
