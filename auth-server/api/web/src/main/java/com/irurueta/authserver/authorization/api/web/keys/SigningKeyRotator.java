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

package com.irurueta.authserver.authorization.api.web.keys;

import com.irurueta.authserver.authorization.application.keys.RotateSigningKeysUseCase;
import com.irurueta.authserver.authorization.application.keys.SigningKeysRotatedEvent;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Runs the key lifecycle and announces it, so every caller (the endpoint, the scheduled job and the startup
 * bootstrap) gets the same cache refresh without depending on the adapter that holds the caches.
 */
@Component
@RequiredArgsConstructor
public class SigningKeyRotator {

    /** Applies the lifecycle transitions that are due. */
    private final RotateSigningKeysUseCase rotateSigningKeysUseCase;

    /** Publishes the rotation event. */
    private final ApplicationEventPublisher eventPublisher;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Applies the lifecycle transitions that are due and publishes a {@link SigningKeysRotatedEvent}: the path of
     * the start-up runner and the scheduled job.
     */
    public void rotate() {
        rotateSigningKeysUseCase.execute();
        published();
    }

    /**
     * Replaces the active key now, whatever its age, and publishes a {@link SigningKeysRotatedEvent}: the path of
     * the administration endpoint.
     */
    public void rotateNow() {
        rotateSigningKeysUseCase.executeForced();
        published();
    }

    /**
     * Publishes the rotation event, so the cached key sets are refreshed.
     */
    private void published() {
        eventPublisher.publishEvent(new SigningKeysRotatedEvent(clock.instant()));
    }
}
