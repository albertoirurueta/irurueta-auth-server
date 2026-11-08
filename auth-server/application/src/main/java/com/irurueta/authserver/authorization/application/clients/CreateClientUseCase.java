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

import com.irurueta.authserver.authorization.domain.clients.ClientAlreadyExistsException;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.clients.ImplicitClientRefusedException;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that registers a client. A client that authenticates with a {@code client_secret_*} method gets a
 * generated secret, stored encoded and returned in clear text only once; a public client and a client that
 * authenticates with {@code private_key_jwt} or mutual TLS only has none.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class CreateClientUseCase {

    /** Port that stores the clients. */
    private final ClientRegistrationRepository clientRegistrationRepository;

    /** Port that encodes secrets. */
    private final PasswordHasher passwordHasher;

    /** Generator of client secrets. */
    private final ClientSecretGenerator clientSecretGenerator;

    // tag::clients-admin[]
    /**
     * Registers a client.
     *
     * @param registration the client.
     * @return the stored client and, for a client that uses a secret, its generated secret;
     *         {@code null} when the client has no {@code client_secret_*} authentication method.
     * @throws ClientAlreadyExistsException if the client id is taken.
     * @throws ImplicitClientRefusedException if the client has the implicit grant type.
     */
    public CreatedClient execute(final ClientRegistration registration) {
        if (registration.usesImplicit()) {
            throw new ImplicitClientRefusedException(registration.clientId());
        }
        if (clientRegistrationRepository.findByClientId(registration.clientId()).isPresent()) {
            throw new ClientAlreadyExistsException(registration.clientId());
        }
        if (!registration.usesClientSecret()) {
            clientRegistrationRepository.save(registration, null);
            return new CreatedClient(registration, null);
        }
        final var secret = clientSecretGenerator.generate();
        clientRegistrationRepository.save(registration, passwordHasher.encode(secret));
        return new CreatedClient(registration, secret);
    }
    // end::clients-admin[]
}
