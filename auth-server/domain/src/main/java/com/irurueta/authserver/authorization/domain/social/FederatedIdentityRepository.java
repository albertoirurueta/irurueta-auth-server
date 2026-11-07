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
package com.irurueta.authserver.authorization.domain.social;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Port that stores the identities of external providers linked to accounts. It never returns {@code null}.
 */
public interface FederatedIdentityRepository {

    /**
     * Finds the link of a provider's subject.
     *
     * @param provider provider that holds the identity.
     * @param subject  stable identifier the provider assigned to the user.
     * @return the link, or an empty optional when that identity is not linked to any account.
     */
    Optional<FederatedIdentity> findByProviderAndSubject(IdentityProvider provider, String subject);

    /**
     * Lists the identities linked to an account, oldest link first.
     *
     * @param userId identifier of the account.
     * @return the links, possibly empty.
     */
    List<FederatedIdentity> findByUser(UUID userId);

    /**
     * Finds one link of an account.
     *
     * @param id     identifier of the link.
     * @param userId identifier of the account, so nobody can reach another account's link.
     * @return the link, or an empty optional when the account has no such link.
     */
    Optional<FederatedIdentity> findByIdAndUser(UUID id, UUID userId);

    /**
     * Stores a link, inserting it or updating the e-mail address and last sign-in instant of an existing one.
     *
     * @param identity link to store.
     * @return the stored link.
     */
    FederatedIdentity save(FederatedIdentity identity);

    /**
     * Deletes a link of an account.
     *
     * @param id     identifier of the link.
     * @param userId identifier of the account.
     * @return {@code true} when a link was deleted.
     */
    boolean delete(UUID id, UUID userId);

    /**
     * Counts the identities linked to an account.
     *
     * @param userId identifier of the account.
     * @return the number of links.
     */
    long countByUser(UUID userId);
}
