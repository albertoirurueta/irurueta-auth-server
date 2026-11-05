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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyGenerator;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyRepository;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RotateSigningKeysUseCase}, with a mocked clock for every state transition.
 */
@ExtendWith(MockitoExtension.class)
class RotateSigningKeysUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");

    /** How long a key signs. */
    private static final Duration INTERVAL = Duration.ofDays(30);

    /** How long a retired key stays published. */
    private static final Duration RETENTION = Duration.ofHours(2);

    /** Number of keys saved by a full rotation: the retired, the promoted and the new next key. */
    private static final int SAVES_ON_ROTATION = 3;

    /** Port that stores the keys. */
    @Mock
    private SigningKeyRepository signingKeyRepository;

    /** Port that generates keys. */
    @Mock
    private SigningKeyGenerator signingKeyGenerator;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    private RotateSigningKeysUseCase useCase;

    /**
     * Creates the use case and makes the mocked lock run its action.
     */
    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(NOW);
        when(signingKeyRepository.withRotationLock(any())).thenAnswer(
                invocation -> invocation.<Supplier<?>>getArgument(0).get());
        useCase = new RotateSigningKeysUseCase(signingKeyRepository, signingKeyGenerator, clock, INTERVAL, RETENTION);
    }

    /**
     * Verifies that the first run creates an active key and a next key.
     */
    @Test
    void execute_whenThereAreNoKeys_createsActiveAndNext() {
        when(signingKeyRepository.findAll()).thenReturn(List.of());
        when(signingKeyGenerator.generate(NOW)).thenReturn(key("k1", SigningKeyStatus.NEXT, NOW),
                key("k2", SigningKeyStatus.NEXT, NOW));

        useCase.execute();

        final var captor = ArgumentCaptor.<SigningKey>captor();
        verify(signingKeyRepository, times(2)).save(captor.capture());
        assertEquals(SigningKeyStatus.ACTIVE, captor.getAllValues().getFirst().status());
        assertEquals("k1", captor.getAllValues().getFirst().kid());
        assertEquals(NOW, captor.getAllValues().getFirst().activatedAt());
        assertEquals(SigningKeyStatus.NEXT, captor.getAllValues().getLast().status());
        assertEquals("k2", captor.getAllValues().getLast().kid());
    }

    /**
     * Verifies that nothing changes while the active key is not due, so a second run is a no-op.
     */
    @Test
    void execute_whenActiveKeyIsNotDue_changesNothing() {
        when(signingKeyRepository.findAll()).thenReturn(List.of(
                key("a", SigningKeyStatus.ACTIVE, NOW.minus(INTERVAL).plusSeconds(1)),
                key("n", SigningKeyStatus.NEXT, NOW)));

        useCase.execute();
        useCase.execute();

        verify(signingKeyRepository, never()).save(any());
        verify(signingKeyRepository, never()).deleteByKid(any());
    }

    /**
     * Verifies that a due active key is retired, the next key promoted and a new next key created.
     */
    @Test
    void execute_whenActiveKeyIsDue_rotatesKeys() {
        when(signingKeyRepository.findAll()).thenReturn(List.of(
                key("a", SigningKeyStatus.ACTIVE, NOW.minus(INTERVAL)), key("n", SigningKeyStatus.NEXT, NOW)));
        when(signingKeyGenerator.generate(NOW)).thenReturn(key("new", SigningKeyStatus.NEXT, NOW));

        useCase.execute();

        final var captor = ArgumentCaptor.<SigningKey>captor();
        verify(signingKeyRepository, times(SAVES_ON_ROTATION)).save(captor.capture());
        final var saved = captor.getAllValues();
        assertEquals(SigningKeyStatus.RETIRED, saved.get(0).status());
        assertEquals("a", saved.get(0).kid());
        assertEquals(NOW, saved.get(0).retiredAt());
        assertEquals(SigningKeyStatus.ACTIVE, saved.get(1).status());
        assertEquals("n", saved.get(1).kid());
        assertEquals(SigningKeyStatus.NEXT, saved.get(2).status());
        assertEquals("new", saved.get(2).kid());
    }

    /**
     * Verifies that the next key is promoted when there is no active key.
     */
    @Test
    void execute_whenThereIsNoActiveKey_promotesNext() {
        when(signingKeyRepository.findAll()).thenReturn(List.of(key("n", SigningKeyStatus.NEXT, NOW)));
        when(signingKeyGenerator.generate(NOW)).thenReturn(key("new", SigningKeyStatus.NEXT, NOW));

        useCase.execute();

        final var captor = ArgumentCaptor.<SigningKey>captor();
        verify(signingKeyRepository, times(2)).save(captor.capture());
        assertEquals(SigningKeyStatus.ACTIVE, captor.getAllValues().getFirst().status());
        assertEquals("n", captor.getAllValues().getFirst().kid());
    }

    /**
     * Verifies that a missing next key is generated.
     */
    @Test
    void execute_whenThereIsNoNextKey_createsOne() {
        when(signingKeyRepository.findAll()).thenReturn(List.of(key("a", SigningKeyStatus.ACTIVE, NOW)));
        final var generated = key("new", SigningKeyStatus.NEXT, NOW);
        when(signingKeyGenerator.generate(NOW)).thenReturn(generated);

        useCase.execute();

        verify(signingKeyRepository).save(generated);
    }

    /**
     * Verifies that only keys retired for longer than the retention are deleted.
     */
    @Test
    void execute_whenKeysAreRetired_deletesOnlyThoseOlderThanRetention() {
        final var old = key("old", SigningKeyStatus.ACTIVE, NOW.minus(INTERVAL)).retire(NOW.minus(RETENTION));
        final var recent = key("recent", SigningKeyStatus.ACTIVE, NOW.minus(INTERVAL))
                .retire(NOW.minus(RETENTION).plusSeconds(1));
        final var unknownRetirement = new SigningKey("legacy", "RS256", "pub", "priv", SigningKeyStatus.RETIRED,
                NOW.minus(RETENTION), null, null);
        when(signingKeyRepository.findAll()).thenReturn(List.of(
                key("a", SigningKeyStatus.ACTIVE, NOW), key("n", SigningKeyStatus.NEXT, NOW), old, recent,
                unknownRetirement));

        useCase.execute();

        verify(signingKeyRepository).deleteByKid("old");
        verify(signingKeyRepository).deleteByKid("legacy");
        verify(signingKeyRepository, never()).deleteByKid("recent");
    }

    /**
     * Verifies that a key without an activation instant is dated from its creation.
     */
    @Test
    void execute_whenActiveKeyHasNoActivationInstant_usesCreationInstant() {
        final var active = new SigningKey("a", "RS256", "pub", "priv", SigningKeyStatus.ACTIVE, NOW.minus(INTERVAL),
                null, null);
        when(signingKeyRepository.findAll()).thenReturn(List.of(active, key("n", SigningKeyStatus.NEXT, NOW)));
        when(signingKeyGenerator.generate(NOW)).thenReturn(key("new", SigningKeyStatus.NEXT, NOW));

        useCase.execute();

        verify(signingKeyRepository).save(active.retire(NOW));
    }

    /**
     * Creates a key.
     *
     * @param kid       identifier.
     * @param status    state.
     * @param createdAt creation instant; also the activation instant of an active key.
     * @return the key.
     */
    private static SigningKey key(final String kid, final SigningKeyStatus status, final Instant createdAt) {
        return new SigningKey(kid, "RS256", "pub", "priv", status, createdAt,
                status == SigningKeyStatus.NEXT ? null : createdAt, null);
    }
}
