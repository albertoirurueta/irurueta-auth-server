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
import com.irurueta.authserver.authorization.domain.keys.SigningKeyRepository;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Use case that finds the keys to publish in the JWKS: the active key, the next key (so relying parties can cache it
 * before it signs) and every retired key whose tokens may still be unexpired.
 */
@Service
@RequiredArgsConstructor
public class PublishedSigningKeysUseCase {

    /** Port that stores the keys. */
    private final SigningKeyRepository signingKeyRepository;

    /** Source of the current time. */
    private final Clock clock;

    /** How long a retired key stays published ({@code authserver.keys.retention}, default 2 hours). */
    @Value("${authserver.keys.retention:PT2H}")
    private final Duration retention;

    /**
     * Finds the keys to publish.
     *
     * @return the active, next and still-valid retired keys.
     */
    public List<SigningKey> execute() {
        final var now = clock.instant();
        return signingKeyRepository.findAll().stream()
                .filter(key -> key.status() != SigningKeyStatus.RETIRED
                        || (key.retiredAt() != null && key.retiredAt().plus(retention).isAfter(now)))
                .toList();
    }
}
