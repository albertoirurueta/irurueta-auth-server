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

package com.irurueta.authserver.authorization.application.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyRepository;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link PublishedSigningKeysUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class PublishedSigningKeysUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");

    /** How long a retired key stays published. */
    private static final Duration RETENTION = Duration.ofHours(2);

    /** Port that stores the keys. */
    @Mock
    private SigningKeyRepository signingKeyRepository;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Decides how long a retired key stays published. */
    @Mock
    private SigningKeyRetention signingKeyRetention;

    /** Use case under test. */
    private PublishedSigningKeysUseCase useCase;

    /**
     * Creates the use case.
     */
    @BeforeEach
    void setUp() {
        useCase = new PublishedSigningKeysUseCase(signingKeyRepository, clock, signingKeyRetention);
    }

    /**
     * Verifies that active, next and still-valid retired keys are published, and expired ones are not.
     */
    @Test
    void execute_whenKeysAreInEveryState_publishesActiveNextAndValidRetired() {
        when(clock.instant()).thenReturn(NOW);
        when(signingKeyRetention.effective()).thenReturn(RETENTION);
        final var active = key("a", SigningKeyStatus.ACTIVE, null);
        final var next = key("n", SigningKeyStatus.NEXT, null);
        final var valid = key("valid", SigningKeyStatus.RETIRED, NOW.minus(RETENTION).plusSeconds(1));
        final var expired = key("expired", SigningKeyStatus.RETIRED, NOW.minus(RETENTION));
        final var unknown = key("unknown", SigningKeyStatus.RETIRED, null);
        when(signingKeyRepository.findAll()).thenReturn(List.of(active, next, valid, expired, unknown));

        assertEquals(List.of(active, next, valid), useCase.execute());
    }

    /**
     * Creates a key.
     *
     * @param kid       identifier.
     * @param status    state.
     * @param retiredAt retirement instant, or {@code null}.
     * @return the key.
     */
    private static SigningKey key(final String kid, final SigningKeyStatus status, final Instant retiredAt) {
        return new SigningKey(kid, "RS256", "pub", "priv", status, NOW.minus(Duration.ofDays(1)), null, retiredAt);
    }
}
