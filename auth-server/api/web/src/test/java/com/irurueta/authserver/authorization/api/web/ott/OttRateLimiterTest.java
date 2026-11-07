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
package com.irurueta.authserver.authorization.api.web.ott;

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

/** Unit tests of {@link OttRateLimiter}, with a mocked clock. */
@ExtendWith(MockitoExtension.class)
class OttRateLimiterTest {

    /** Start of the first window. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Length of a window. */
    private static final Duration WINDOW = Duration.ofMinutes(15);

    /** Token requests one client address may make in a window. */
    private static final int GENERATION_CLIENT = 3;

    /** Token requests that may name one identifier in a window. */
    private static final int GENERATION_IDENTIFIER = 2;

    /** Submissions one client address may make in a window. */
    private static final int VERIFICATION_CLIENT = 4;

    /** Submissions that may name one identifier in a window. */
    private static final int VERIFICATION_IDENTIFIER = 2;

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

    /** An identifier. */
    private static final String IDENTIFIER = "Alice";

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** A client over its token request limit is told how long to wait; the others are counted apart. */
    @Test
    void checkGeneration_whenClientExceedsItsLimit_throwsWithTheRestOfTheWindow() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        for (var i = 0; i < GENERATION_CLIENT; i++) {
            limiter.checkGeneration(CLIENT, null);
        }
        when(clock.instant()).thenReturn(NOW.plusSeconds(LATE_SECONDS));

        final var error = assertThrows(OttRateLimitExceededException.class,
                () -> limiter.checkGeneration(CLIENT, null));

        assertEquals(WINDOW.minusSeconds(LATE_SECONDS), error.getRetryAfter());
        assertDoesNotThrow(() -> limiter.checkGeneration(OTHER_CLIENT, null));
    }

    /** An identifier is limited across clients, ignoring case. */
    @Test
    void checkGeneration_whenOneIdentifierIsNamedFromManyClients_isLimitedPerIdentifier() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        limiter.checkGeneration(CLIENT, IDENTIFIER);
        limiter.checkGeneration(OTHER_CLIENT, IDENTIFIER.toUpperCase(Locale.ROOT));

        assertThrows(OttRateLimitExceededException.class, () -> limiter.checkGeneration(THIRD_CLIENT, IDENTIFIER));
    }

    /** Submissions have limits of their own, apart from the token requests. */
    @Test
    void checkVerification_whenSubmissionsExceedTheLimit_throwsWithoutCountingTokenRequests() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        limiter.checkVerification(CLIENT, IDENTIFIER);
        limiter.checkVerification(OTHER_CLIENT, IDENTIFIER);

        assertThrows(OttRateLimitExceededException.class, () -> limiter.checkVerification(THIRD_CLIENT, IDENTIFIER));
        assertDoesNotThrow(() -> limiter.checkGeneration(THIRD_CLIENT, IDENTIFIER));
    }

    /** A submission of a magic link names no identifier and is only limited per client. */
    @Test
    void checkVerification_whenNoIdentifier_isLimitedPerClientOnly() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        for (var i = 0; i < VERIFICATION_CLIENT; i++) {
            limiter.checkVerification(CLIENT, null);
        }

        assertThrows(OttRateLimitExceededException.class, () -> limiter.checkVerification(CLIENT, null));
    }

    /** An unknown client address is counted as one client. */
    @Test
    void checkGeneration_whenClientAddressIsUnknown_countsThemTogether() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        for (var i = 0; i < GENERATION_CLIENT; i++) {
            limiter.checkGeneration(null, null);
        }

        assertThrows(OttRateLimitExceededException.class, () -> limiter.checkGeneration(null, null));
    }

    /** A new window starts once the previous one has elapsed. */
    @Test
    void checkGeneration_whenTheWindowHasElapsed_acceptsAgain() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        for (var i = 0; i < GENERATION_CLIENT; i++) {
            limiter.checkGeneration(CLIENT, null);
        }
        when(clock.instant()).thenReturn(NOW.plus(WINDOW));

        assertDoesNotThrow(() -> limiter.checkGeneration(CLIENT, null));
    }

    /** A disabled limiter never rejects. */
    @Test
    void checkGeneration_whenDisabled_neverRejects() {
        final var limiter = limiter(false);

        for (var i = 0; i < GENERATION_CLIENT + 1; i++) {
            assertDoesNotThrow(() -> limiter.checkGeneration(CLIENT, IDENTIFIER));
        }
    }

    /** The tracked keys stay within their bound. */
    @Test
    void trackedKeys_whenMoreKeysThanTheBound_staysBounded() {
        final var limiter = limiter(true);
        when(clock.instant()).thenReturn(NOW);
        limiter.checkGeneration(CLIENT, null);
        limiter.checkGeneration(OTHER_CLIENT, null);
        limiter.checkGeneration(THIRD_CLIENT, null);

        assertEquals(MAX_KEYS, limiter.trackedKeys());
    }

    /**
     * Builds the limiter under test.
     *
     * @param enabled whether it limits.
     * @return the limiter.
     */
    private OttRateLimiter limiter(final boolean enabled) {
        return new OttRateLimiter(new OttRateLimitProperties(enabled, WINDOW, GENERATION_CLIENT,
                GENERATION_IDENTIFIER, VERIFICATION_CLIENT, VERIFICATION_IDENTIFIER, MAX_KEYS), clock);
    }
}
