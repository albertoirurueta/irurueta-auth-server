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

package com.irurueta.authserver.bff.api.web.user;

import com.irurueta.authserver.bff.api.web.v1.generated.model.SessionUserResponse;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

/**
 * Maps the OpenID Connect user of the BFF session onto the DTO generated from the contract. The BFF has no domain
 * yet, so the source is the Spring Security principal; only its subject is ever exposed.
 */
@Component
public class SessionUserDtoMapper {

    /**
     * Maps the signed-in user.
     *
     * @param user the authenticated OIDC user.
     * @return its web representation, holding the subject only.
     */
    public SessionUserResponse toResponse(final OidcUser user) {
        return new SessionUserResponse(user.getSubject());
    }
}
