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

package com.irurueta.authserver.authorization.api.web.account;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link AccountRateLimiter}, with a mocked clock.
 */
@ExtendWith(MockitoExtension.class)
class AccountRateLimiterTest {

    /** Start of the first window. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Length of a window. */
    private static final Duration WINDOW = Duration.ofMinutes(15);

    /** Requests one client address may make in a window. */
    private static final int PER_CLIENT = 3;

    /** Requests that may name one e-mail address in a window. */
    private static final int PER_EMAIL = 2;

    /** Keys tracked at most per kind. */
    private static final int MAX_KEYS = 2;

    /** Seconds into the window of the request that is rejected. */
    private static final long LATE_SECONDS = 60;

    /** A client address. */
    private static final String CLIENT = "192.0.2.1";

    /** Another client address. */
    private static final String OTHER_CLIENT = "192.0.2.2";

    /** A third client address. */
    private static final String THIRD_CLIENT = "192.0.2.3";

    /** An e-mail address. */
    private static final String EMAIL = "alice@example.com";

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /**
     * Verifies that a client is limited once it exceeds its requests in a window, and is told how long to wait.
     */
    @Test
    void check_whenClientExceedsItsLimit_throwsWithTheRestOfTheWindow() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        for (var i = 0; i < PER_CLIENT; i++) {
            limiter.check(CLIENT, null);
        }
        when(clock.instant()).thenReturn(NOW.plusSeconds(LATE_SECONDS));

        final var error = assertThrows(AccountRateLimitExceededException.class, () -> limiter.check(CLIENT, null));

        assertEquals(WINDOW.minusSeconds(LATE_SECONDS), error.getRetryAfter());
        assertDoesNotThrow(() -> limiter.check(OTHER_CLIENT, null), "other clients are counted apart");
    }

    /**
     * Verifies that an e-mail address is limited across clients, ignoring case.
     */
    @Test
    void check_whenOneEmailIsNamedFromManyClients_isLimitedPerEmail() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        limiter.check(CLIENT, EMAIL);
        limiter.check(OTHER_CLIENT, EMAIL.toUpperCase(Locale.ROOT));

        assertThrows(AccountRateLimitExceededException.class, () -> limiter.check(THIRD_CLIENT, EMAIL));
    }

    /**
     * Verifies that a new window starts once the previous one has elapsed.
     */
    @Test
    void check_whenTheWindowHasElapsed_acceptsAgain() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        for (var i = 0; i < PER_CLIENT; i++) {
            limiter.check(CLIENT, null);
        }
        when(clock.instant()).thenReturn(NOW.plus(WINDOW));

        assertDoesNotThrow(() -> limiter.check(CLIENT, null));
    }

    /**
     * Verifies that the counters stay bounded: tracking more keys than allowed forgets the oldest, whose count
     * starts again.
     */
    @Test
    void check_whenMoreKeysThanTrackedArrive_forgetsTheOldest() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        for (var i = 0; i < PER_CLIENT; i++) {
            limiter.check(CLIENT, null);
        }
        limiter.check(OTHER_CLIENT, null);
        limiter.check(THIRD_CLIENT, null);

        assertDoesNotThrow(() -> limiter.check(CLIENT, null));
    }

    /**
     * Verifies that a disabled limiter accepts everything without reading the clock.
     */
    @Test
    void check_whenDisabled_neverLimits() {
        final var limiter = limiter(false);

        for (var i = 0; i <= PER_CLIENT; i++) {
            assertDoesNotThrow(() -> limiter.check(CLIENT, EMAIL));
        }
    }

    /**
     * Creates the limiter under test.
     *
     * @param enabled whether it limits.
     * @return the limiter.
     */
    private AccountRateLimiter limiter(final boolean enabled) {
        return new AccountRateLimiter(new AccountRateLimitProperties(enabled, WINDOW, PER_CLIENT, PER_EMAIL,
                MAX_KEYS), clock);
    }
}
