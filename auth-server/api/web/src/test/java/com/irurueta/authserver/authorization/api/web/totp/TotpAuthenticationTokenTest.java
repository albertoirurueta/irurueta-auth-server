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

package com.irurueta.authserver.authorization.api.web.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * Unit tests of {@link TotpAuthenticationToken}.
 */
class TotpAuthenticationTokenTest {

    /** The code. */
    private static final String CODE = "123456";

    /** The authentication the user already holds. */
    private final UsernamePasswordAuthenticationToken primary =
            UsernamePasswordAuthenticationToken.authenticated("alice", "secret", java.util.List.of());

    /**
     * Verifies the accessors of a TOTP request.
     */
    @Test
    void constructor_whenTotpCode_exposesItsParts() {
        final var token = new TotpAuthenticationToken(primary, CODE, false);

        assertSame(primary, token.primary());
        assertEquals("alice", token.getPrincipal());
        assertEquals(CODE, token.getCredentials());
        assertFalse(token.isRecovery());
        assertFalse(token.isAuthenticated());
    }

    /**
     * Verifies that a recovery request is flagged and that equality follows its fields.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var token = new TotpAuthenticationToken(primary, CODE, true);
        final var same = new TotpAuthenticationToken(primary, CODE, true);
        final var other = new TotpAuthenticationToken(primary, "654321", true);

        assertTrue(token.isRecovery());
        assertEquals(token, same);
        assertEquals(token.hashCode(), same.hashCode());
        assertFalse(token.equals(other));
    }
}
