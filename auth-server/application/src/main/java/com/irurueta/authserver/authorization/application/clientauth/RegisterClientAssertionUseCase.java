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

package com.irurueta.authserver.authorization.application.clientauth;

import com.irurueta.authserver.authorization.domain.clientauth.ClientAssertionReplayRegistry;
import com.irurueta.authserver.authorization.domain.clientauth.ClientAssertionUse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records the use of a client assertion and tells whether it is a replay.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class RegisterClientAssertionUseCase {

    /** Port that remembers the accepted assertions. */
    private final ClientAssertionReplayRegistry registry;

    /**
     * Registers the use of an assertion.
     *
     * @param use the client, identifier and expiry of the assertion.
     * @return {@code true} when this is the first use of the assertion, {@code false} when it was already used.
     */
    public boolean execute(final ClientAssertionUse use) {
        return registry.register(use.clientId(), use.jti(), use.expiresAt());
    }
}
