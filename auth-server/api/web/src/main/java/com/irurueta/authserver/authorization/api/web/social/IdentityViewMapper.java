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

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Maps the linked identities of the domain onto the view model of the identities page.
 */
@Component
public class IdentityViewMapper {

    /**
     * Maps an identity.
     *
     * @param identity the identity.
     * @return its view.
     */
    public IdentityView toView(final FederatedIdentity identity) {
        return new IdentityView(identity.provider().id(), identity.email(), identity.linkedAt());
    }

    /**
     * Maps several identities, keeping their order.
     *
     * @param identities the identities.
     * @return their views.
     */
    public List<IdentityView> toViews(final List<FederatedIdentity> identities) {
        return identities.stream().map(this::toView).toList();
    }
}
