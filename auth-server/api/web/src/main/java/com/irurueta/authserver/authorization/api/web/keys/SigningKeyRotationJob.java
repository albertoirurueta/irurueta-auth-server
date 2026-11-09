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

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

// tag::keys-rotation-job[]
/**
 * Periodically applies the key lifecycle. The schedule is the cron expression {@code authserver.keys.rotation.cron}
 * (default: every hour); the use case itself only changes keys that are due.
 */
@Component
@RequiredArgsConstructor
public class SigningKeyRotationJob {

    /** Rotates the keys. */
    private final SigningKeyRotator signingKeyRotator;

    /**
     * Rotates the keys.
     */
    @Scheduled(cron = "${authserver.keys.rotation.cron:0 0 * * * *}")
    public void run() {
        signingKeyRotator.rotate();
    }
}
// end::keys-rotation-job[]
