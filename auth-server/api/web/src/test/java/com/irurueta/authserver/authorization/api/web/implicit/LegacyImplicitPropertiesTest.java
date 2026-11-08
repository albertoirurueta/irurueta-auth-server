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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link LegacyImplicitProperties}.
 */
class LegacyImplicitPropertiesTest {

    /** Minutes of the longest lifetime. */
    private static final int MAX_MINUTES = 15;

    /** Client id. */
    private static final String CLIENT_ID = "legacy-implicit-spa";

    /** Redirect URI. */
    private static final String REDIRECT_URI = "http://localhost:9000/legacy-implicit/";

    /** Audience. */
    private static final String AUDIENCE = "resource-server";

    /** A valid scope. */
    private static final String SCOPE = "documents.read";

    /** A valid lifetime. */
    private static final Duration TTL = Duration.ofMinutes(5);

    /**
     * Verifies that valid settings are kept.
     */
    @Test
    void constructor_whenSettingsAreValid_keepsThem() {
        final var properties = new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, List.of(SCOPE), AUDIENCE, TTL);

        assertEquals(CLIENT_ID, properties.clientId());
        assertEquals(REDIRECT_URI, properties.redirectUri());
        assertEquals(List.of(SCOPE), properties.scopes());
        assertEquals(AUDIENCE, properties.audience());
        assertEquals(TTL, properties.accessTokenTtl());
    }

    /**
     * Verifies that the longest allowed lifetime is accepted.
     */
    @Test
    void constructor_whenLifetimeIsTheMaximum_isAccepted() {
        final var properties = new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, List.of(SCOPE), AUDIENCE,
                LegacyImplicitProperties.MAX_ACCESS_TOKEN_TTL);

        assertEquals(Duration.ofMinutes(MAX_MINUTES), properties.accessTokenTtl());
    }

    /**
     * Verifies that a lifetime above fifteen minutes is refused.
     */
    @Test
    void constructor_whenLifetimeExceedsTheMaximum_throwsIllegalArgumentException() {
        final var tooLong = LegacyImplicitProperties.MAX_ACCESS_TOKEN_TTL.plusSeconds(1);

        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, List.of(SCOPE), AUDIENCE, tooLong));
    }

    /**
     * Verifies that a missing, zero or negative lifetime is refused.
     */
    @Test
    void constructor_whenLifetimeIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, List.of(SCOPE), AUDIENCE, null));
        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, List.of(SCOPE), AUDIENCE, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI,
                List.of(SCOPE), AUDIENCE, Duration.ofSeconds(-1)));
    }

    /**
     * Verifies that a blank client id, redirect URI or audience is refused.
     */
    @Test
    void constructor_whenATextIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(" ", REDIRECT_URI, List.of(SCOPE), AUDIENCE, TTL));
        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(CLIENT_ID, null, List.of(SCOPE), AUDIENCE, TTL));
        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, List.of(SCOPE), "", TTL));
    }

    /**
     * Verifies that missing, empty or blank scopes are refused.
     */
    @Test
    void constructor_whenScopesAreInvalid_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, null, AUDIENCE, TTL));
        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, List.of(), AUDIENCE, TTL));
        assertThrows(IllegalArgumentException.class,
                () -> new LegacyImplicitProperties(CLIENT_ID, REDIRECT_URI, List.of(" "), AUDIENCE, TTL));
    }
}
