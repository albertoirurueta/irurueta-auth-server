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

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that looks a client up by its identifier.
 */
@Service
@RequiredArgsConstructor
public class GetClientUseCase {

    /** Port that stores the clients. */
    private final ClientRegistrationRepository clientRegistrationRepository;

    /**
     * Finds a client.
     *
     * @param clientId public identifier of the client.
     * @return the client, or an empty optional when it is not registered.
     */
    public Optional<ClientRegistration> execute(final String clientId) {
        return clientRegistrationRepository.findByClientId(clientId);
    }
}
