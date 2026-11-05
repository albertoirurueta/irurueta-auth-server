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

package com.irurueta.authserver.resourceserver;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only endpoint: the security tests need one path that no rule of the filter chain names, to prove that a
 * bearer JWT with the resource server's audience is required (the default rule) and that its claims reach the
 * application. It lives in the test sources, so it never ships in the jar.
 */
@RestController
public class ProtectedTestController {

    /** Path of the protected test endpoint. */
    public static final String PATH = "/test/protected";

    /**
     * Returns the subject of the bearer token.
     *
     * @param jwt validated bearer token of the request.
     * @return the subject of the token.
     */
    @GetMapping(PATH)
    public String subject(@AuthenticationPrincipal final Jwt jwt) {
        return jwt.getSubject();
    }
}
