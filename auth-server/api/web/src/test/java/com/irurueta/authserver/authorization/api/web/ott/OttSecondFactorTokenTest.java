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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

/** Unit tests of {@link OttSecondFactorToken}. */
class OttSecondFactorTokenTest {

    /** The request exposes its parts and is never authenticated. */
    @Test
    void constructor_whenCreated_exposesItsPartsAndIsNotAuthenticated() {
        final var primary = UsernamePasswordAuthenticationToken.authenticated("alice", "x",
                AuthorityUtils.NO_AUTHORITIES);
        final var token = new OttSecondFactorToken(primary, "123456", "binding");

        assertSame(primary, token.primary());
        assertEquals("alice", token.getPrincipal());
        assertEquals("123456", token.getCredentials());
        assertEquals("binding", token.bindingId());
        assertFalse(token.isAuthenticated());
    }
}
