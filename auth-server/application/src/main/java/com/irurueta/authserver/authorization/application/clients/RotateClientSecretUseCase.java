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

package com.irurueta.authserver.authorization.application.clients;

import com.irurueta.authserver.authorization.domain.clients.ClientNotFoundException;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that replaces the secret of a confidential client with a new generated one.
 */
@Service
@RequiredArgsConstructor
public class RotateClientSecretUseCase {

    /** Port that stores the clients. */
    private final ClientRegistrationRepository clientRegistrationRepository;

    /** Port that encodes secrets. */
    private final PasswordHasher passwordHasher;

    /** Generator of client secrets. */
    private final ClientSecretGenerator clientSecretGenerator;

    /**
     * Rotates the secret of a client.
     *
     * @param clientId public identifier of the client.
     * @return the new clear-text secret, shown only this once.
     * @throws ClientNotFoundException  if the client is not registered.
     * @throws IllegalArgumentException if the client is public and so has no secret.
     */
    public String execute(final String clientId) {
        final var registration = clientRegistrationRepository.findByClientId(clientId)
                .orElseThrow(() -> new ClientNotFoundException(clientId));
        if (!registration.confidential()) {
            throw new IllegalArgumentException("Client '" + clientId + "' is public and has no secret");
        }
        final var secret = clientSecretGenerator.generate();
        clientRegistrationRepository.updateSecret(clientId, passwordHasher.encode(secret));
        return secret;
    }
}
