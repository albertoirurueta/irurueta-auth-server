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
import java.util.List;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

/**
 * Maps the OpenID Connect user of the BFF session onto the DTO generated from the contract. The BFF has no domain
 * yet, so the source is the Spring Security principal; only UI-safe claims are ever exposed, never a token.
 */
@Component
public class SessionUserDtoMapper {

    /** ID token claim holding the roles of the user, as issued by the authorization server. */
    static final String ROLES_CLAIM = "roles";

    /**
     * Maps the signed-in user.
     *
     * @param user the authenticated OIDC user.
     * @return its web representation: subject, display name, email and roles.
     */
    public SessionUserResponse toResponse(final OidcUser user) {
        final var roles = user.getClaimAsStringList(ROLES_CLAIM);
        return new SessionUserResponse(user.getSubject(), displayName(user), user.getEmail(),
                roles == null ? List.of() : List.copyOf(roles));
    }

    /**
     * Picks the best display name the ID token offers.
     *
     * @param user the authenticated OIDC user.
     * @return the full name, else the preferred username, else {@code null}.
     */
    private static String displayName(final OidcUser user) {
        final var fullName = user.getFullName();
        return fullName != null ? fullName : user.getPreferredUsername();
    }
}
