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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

/**
 * Unit tests of {@link SessionUserDtoMapper}.
 */
class SessionUserDtoMapperTest {

    /** Subject used by the tests. */
    private static final String SUBJECT = "demo-user";

    /** Seconds the ID token lives. */
    private static final long TOKEN_LIFETIME_SECONDS = 60;

    /** Mapper under test. */
    private final SessionUserDtoMapper mapper = new SessionUserDtoMapper();

    /**
     * Verifies that subject, name, email and roles are exposed, and nothing else of the token.
     */
    @Test
    void toResponse_whenIdTokenHasAllClaims_exposesThem() {
        final var user = user(Map.of("sub", SUBJECT, "name", "Demo User", "email", "demo@example.com",
                "roles", List.of("ROLE_USER", "ROLE_ADMIN")));

        final var response = mapper.toResponse(user);

        assertEquals(SUBJECT, response.subject());
        assertEquals("Demo User", response.name());
        assertEquals("demo@example.com", response.email());
        assertEquals(List.of("ROLE_USER", "ROLE_ADMIN"), response.roles());
    }

    /**
     * Verifies that the preferred username stands in for a missing full name, and that missing roles give an empty
     * list.
     */
    @Test
    void toResponse_whenOnlySubjectAndUsernameArePresent_usesUsernameAndNoRoles() {
        final var response = mapper.toResponse(user(Map.of("sub", SUBJECT, "preferred_username", "demo")));

        assertEquals("demo", response.name());
        assertNull(response.email());
        assertTrue(response.roles().isEmpty());
    }

    /**
     * Builds an OIDC user whose ID token carries the given claims.
     *
     * @param claims claims of the ID token.
     * @return the user.
     */
    private static DefaultOidcUser user(final Map<String, Object> claims) {
        final var now = Instant.now();
        final var token = new OidcIdToken("token-value", now, now.plusSeconds(TOKEN_LIFETIME_SECONDS), claims);
        return new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
    }
}
