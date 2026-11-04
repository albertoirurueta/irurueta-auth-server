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

package com.irurueta.authserver.bff.user;

import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes the authenticated user.
 */
@RestController
public class UserController {

    // tag::bff-user[]
    /**
     * Returns the subject of the authenticated user.
     *
     * @param user the authenticated OIDC user.
     * @return a map holding the subject.
     */
    @GetMapping("/bff/user")
    public Map<String, String> user(@AuthenticationPrincipal final OidcUser user) {
        return Map.of("subject", user.getSubject());
    }
    // end::bff-user[]
}
