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

import com.irurueta.authserver.bff.api.web.v1.generated.api.UserApi;
import com.irurueta.authserver.bff.api.web.v1.generated.model.SessionUserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes the authenticated user, as the contract {@code apis/bff/rest-server/bff-api-v1.yaml} describes it through
 * the generated {@link UserApi}.
 */
@RestController
@RequiredArgsConstructor
public class UserController implements UserApi {

    /** Maps the signed-in user onto the generated DTO. */
    private final SessionUserDtoMapper sessionUserDtoMapper;

    // tag::bff-user[]
    /**
     * Returns the subject of the authenticated user. The security chain answers 401 before reaching this method when
     * nobody is signed in, so the principal of the security context is always the OIDC user of the session.
     *
     * @return the signed-in user's subject.
     * @throws AuthenticationCredentialsNotFoundException if no OIDC user is signed in, answered 401 by the chain.
     */
    @Override
    public ResponseEntity<SessionUserResponse> getSessionUser() {
        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof final OidcUser user)) {
            throw new AuthenticationCredentialsNotFoundException("No OpenID Connect user is signed in");
        }
        return ResponseEntity.ok(sessionUserDtoMapper.toResponse(user));
    }
    // end::bff-user[]
}
