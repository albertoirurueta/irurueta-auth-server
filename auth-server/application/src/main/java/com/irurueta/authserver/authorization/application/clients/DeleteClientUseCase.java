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
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that deletes a registered client.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class DeleteClientUseCase {

    /** Port that stores the clients. */
    private final ClientRegistrationRepository clientRegistrationRepository;

    /**
     * Deletes a client.
     *
     * @param clientId public identifier of the client.
     * @throws ClientNotFoundException if the client is not registered.
     */
    public void execute(final String clientId) {
        if (clientRegistrationRepository.findByClientId(clientId).isEmpty()) {
            throw new ClientNotFoundException(clientId);
        }
        clientRegistrationRepository.deleteByClientId(clientId);
    }
}
