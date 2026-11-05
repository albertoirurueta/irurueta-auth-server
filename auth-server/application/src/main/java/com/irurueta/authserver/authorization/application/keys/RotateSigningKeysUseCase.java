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

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyGenerator;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyRepository;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Use case that keeps the signing keys rotating. One call, made at start-up and then on a schedule, does whatever is
 * due: it creates the {@code active} and {@code next} keys when they are missing, promotes {@code next} to
 * {@code active} and retires the old {@code active} key once the rotation interval has elapsed, always leaves a
 * fresh {@code next} key behind, and deletes keys retired for longer than the retention. A second call right after
 * the first changes nothing, and the whole call runs under the repository's rotation lock, so several instances can
 * call it safely.
 */
@Service
@RequiredArgsConstructor
public class RotateSigningKeysUseCase {

    /** Port that stores the keys. */
    private final SigningKeyRepository signingKeyRepository;

    /** Port that generates keys. */
    private final SigningKeyGenerator signingKeyGenerator;

    /** Source of the current time. */
    private final Clock clock;

    /** How long a key signs before it is replaced ({@code authserver.keys.rotation-interval}, default 30 days). */
    @Value("${authserver.keys.rotation-interval:P30D}")
    private final Duration rotationInterval;

    /**
     * How long a retired key stays published: the longest token lifetime plus the clock skew
     * ({@code authserver.keys.retention}, default 2 hours).
     */
    @Value("${authserver.keys.retention:PT2H}")
    private final Duration retention;

    // tag::keys-rotation[]
    /**
     * Does whatever the key lifecycle requires at the current instant.
     */
    public void execute() {
        final var now = clock.instant();
        signingKeyRepository.withRotationLock(() -> {
            rotate(now);
            return null;
        });
    }

    /**
     * Applies the lifecycle transitions that are due.
     *
     * @param now current instant.
     */
    private void rotate(final Instant now) {
        final var keys = signingKeyRepository.findAll();
        var active = first(keys, SigningKeyStatus.ACTIVE);
        var next = first(keys, SigningKeyStatus.NEXT);
        if (active != null && isDue(active, now)) {
            signingKeyRepository.save(active.retire(now));
            active = null;
        }
        if (active == null) {
            final var promoted = next != null ? next : signingKeyGenerator.generate(now);
            signingKeyRepository.save(promoted.activate(now));
            next = null;
        }
        if (next == null) {
            signingKeyRepository.save(signingKeyGenerator.generate(now));
        }
        keys.stream()
                .filter(key -> key.status() == SigningKeyStatus.RETIRED && isExpired(key, now))
                .forEach(key -> signingKeyRepository.deleteByKid(key.kid()));
    }
    // end::keys-rotation[]

    /**
     * Finds the first key in a state.
     *
     * @param keys   the keys.
     * @param status the state.
     * @return the key, or {@code null} when none is in that state.
     */
    private static SigningKey first(final List<SigningKey> keys, final SigningKeyStatus status) {
        return keys.stream().filter(key -> key.status() == status).findFirst().orElse(null);
    }

    /**
     * Tells whether the active key has signed for the whole rotation interval.
     *
     * @param active the active key.
     * @param now    current instant.
     * @return {@code true} when it must be replaced.
     */
    private boolean isDue(final SigningKey active, final Instant now) {
        final var since = active.activatedAt() == null ? active.createdAt() : active.activatedAt();
        return !since.plus(rotationInterval).isAfter(now);
    }

    /**
     * Tells whether a retired key has been retired for longer than the retention.
     *
     * @param retired the retired key.
     * @param now     current instant.
     * @return {@code true} when it can be deleted.
     */
    private boolean isExpired(final SigningKey retired, final Instant now) {
        final var since = retired.retiredAt() == null ? retired.createdAt() : retired.retiredAt();
        return !since.plus(retention).isAfter(now);
    }
}
