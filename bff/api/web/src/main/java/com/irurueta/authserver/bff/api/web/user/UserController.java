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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes the authenticated user.
 */
@RestController
@Tag(name = "User", description = "The user signed in to the BFF session")
public class UserController {

    // tag::bff-user[]
    /**
     * Returns the subject of the authenticated user.
     *
     * @param user the authenticated OIDC user.
     * @return the signed-in user's subject.
     */
    @GetMapping("/bff/user")
    @Operation(summary = "Returns the signed-in user", responses = {
            @ApiResponse(responseCode = "200", description = "The signed-in user"),
            @ApiResponse(responseCode = "401", description = "There is no signed-in user", content = @Content)})
    public SessionUserResponse user(@Parameter(hidden = true) @AuthenticationPrincipal final OidcUser user) {
        return new SessionUserResponse(user.getSubject());
    }
    // end::bff-user[]
}
