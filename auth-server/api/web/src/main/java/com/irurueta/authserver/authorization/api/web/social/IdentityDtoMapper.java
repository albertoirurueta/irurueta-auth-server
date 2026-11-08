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

package com.irurueta.authserver.authorization.api.web.social;

import com.irurueta.authserver.authorization.api.web.v1.generated.model.Identity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Maps the linked identities of the domain onto the DTO generated from the contract. The subject the provider
 * assigned to the user, and the account the identity belongs to, are not part of the contract and never leave the
 * server.
 */
@Component
public class IdentityDtoMapper {

    /**
     * Maps an identity to its public view.
     *
     * @param identity the identity.
     * @return its public view.
     */
    public Identity toResponse(final FederatedIdentity identity) {
        return new Identity(identity.id(), Identity.ProviderEnum.fromValue(identity.provider().id()),
                identity.email(), identity.linkedAt(), identity.lastLoginAt());
    }

    /**
     * Maps several identities, keeping their order.
     *
     * @param identities the identities.
     * @return their public views.
     */
    public List<Identity> toResponses(final List<FederatedIdentity> identities) {
        return identities.stream().map(this::toResponse).toList();
    }
}
