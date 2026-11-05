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
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that finds the one key that signs new tokens.
 */
@Service
@RequiredArgsConstructor
public class ActiveSigningKeyUseCase {

    /** Port that stores the keys. */
    private final SigningKeyRepository signingKeyRepository;

    /**
     * Finds the active key.
     *
     * @return the active key, or an empty optional before the first rotation has run.
     */
    public Optional<SigningKey> execute() {
        return signingKeyRepository.findAll().stream()
                .filter(key -> key.status() == SigningKeyStatus.ACTIVE)
                .findFirst();
    }
}
