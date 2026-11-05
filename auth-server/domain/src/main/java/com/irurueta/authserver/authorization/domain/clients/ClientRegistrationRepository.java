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

package com.irurueta.authserver.authorization.domain.clients;

import java.util.List;
import java.util.Optional;

/**
 * Port that stores registered clients. An implementation never returns {@code null}.
 */
public interface ClientRegistrationRepository {

    /**
     * Finds a client by its identifier.
     *
     * @param clientId public identifier of the client.
     * @return the client, or an empty optional when it is not registered.
     */
    Optional<ClientRegistration> findByClientId(String clientId);

    /**
     * Finds every registered client.
     *
     * @return the clients; empty when there are none.
     */
    List<ClientRegistration> findAll();

    /**
     * Inserts a client, or replaces the settings of the stored client that has the same identifier.
     *
     * @param registration  the client.
     * @param encodedSecret the encoded client secret, or {@code null} to keep the stored one (a public client has
     *                      none).
     */
    void save(ClientRegistration registration, String encodedSecret);

    /**
     * Deletes a client.
     *
     * @param clientId public identifier of the client.
     */
    void deleteByClientId(String clientId);

    /**
     * Replaces the secret of a client.
     *
     * @param clientId      public identifier of the client.
     * @param encodedSecret the new encoded secret.
     */
    void updateSecret(String clientId, String encodedSecret);
}
