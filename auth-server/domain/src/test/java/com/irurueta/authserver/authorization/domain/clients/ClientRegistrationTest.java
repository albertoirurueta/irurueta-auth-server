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

package com.irurueta.authserver.authorization.domain.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientRegistration}.
 */
class ClientRegistrationTest {

    /** Client id used by the tests. */
    private static final String CLIENT_ID = "bff";

    /** Positive lifetime used by the tests. */
    private static final Duration TTL = Duration.ofMinutes(1);

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var client = create(CLIENT_ID, "Name", true, true, List.of("api"), TTL, TTL);

        assertEquals(CLIENT_ID, client.clientId());
        assertEquals(List.of("api"), client.audiences());
        assertEquals(List.of("openid"), client.scopes());
    }

    /**
     * Verifies that the client id is the audience when none is given.
     */
    @Test
    void constructor_whenAudiencesAreEmpty_defaultsToClientId() {
        final var client = create(CLIENT_ID, "Name", true, true, List.of(), TTL, TTL);

        assertEquals(List.of(CLIENT_ID), client.audiences());
    }

    /**
     * Verifies that a blank id, name or format is rejected.
     */
    @Test
    void constructor_whenIdOrNameIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> create(" ", "Name", true, true, List.of(), TTL, TTL));
        assertThrows(IllegalArgumentException.class, () -> create(CLIENT_ID, null, true, true, List.of(), TTL, TTL));
        assertThrows(IllegalArgumentException.class, () -> new ClientRegistration(CLIENT_ID, "Name", true,
                List.of(), List.of(), List.of(), List.of(), true, List.of(), TTL, TTL, "", false, List.of(), false,
                false));
    }

    /**
     * Verifies that null collections and null elements are rejected.
     */
    @Test
    void constructor_whenCollectionIsInvalid_throwsIllegalArgumentException() {
        final var withNull = new ArrayList<String>();
        withNull.add(null);

        assertThrows(IllegalArgumentException.class, () -> new ClientRegistration(CLIENT_ID, "Name", true, null,
                List.of(), List.of(), List.of(), true, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false));
        assertThrows(IllegalArgumentException.class, () -> new ClientRegistration(CLIENT_ID, "Name", true,
                List.of(), List.of(), List.of(), withNull, true, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false));
    }

    /**
     * Verifies that missing, zero and negative lifetimes are rejected.
     */
    @Test
    void constructor_whenLifetimeIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> create(CLIENT_ID, "Name", true, true, List.of(), null, TTL));
        assertThrows(IllegalArgumentException.class,
                () -> create(CLIENT_ID, "Name", true, true, List.of(), TTL, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> create(CLIENT_ID, "Name", true, true, List.of(), TTL, TTL.negated()));
    }

    /**
     * Verifies that a public client without PKCE is rejected, while a confidential one may skip it.
     */
    @Test
    void constructor_whenPublicClientSkipsPkce_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> create(CLIENT_ID, "Name", false, false, List.of(), TTL, TTL));
        assertEquals(CLIENT_ID, create(CLIENT_ID, "Name", true, false, List.of(), TTL, TTL).clientId());
    }

    /**
     * Creates a registration.
     *
     * @param id           client id.
     * @param name         name.
     * @param confidential whether confidential.
     * @param pkce         whether PKCE is required.
     * @param audiences    audiences.
     * @param access       access token lifetime.
     * @param refresh      refresh token lifetime.
     * @return the registration.
     */
    private static ClientRegistration create(
            final String id, final String name, final boolean confidential, final boolean pkce,
            final List<String> audiences, final Duration access, final Duration refresh) {
        return new ClientRegistration(id, name, confidential, List.of("none"), List.of("authorization_code"),
                List.of("http://localhost/cb"), List.of("openid"), pkce, audiences, access, refresh,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false);
    }

    /**
     * Verifies that post-logout redirect URIs are copied and that a null list or a null element is rejected.
     */
    @Test
    void constructor_whenPostLogoutRedirectUrisAreGiven_copiesThemAndRejectsNulls() {
        final var uris = new ArrayList<>(List.of("https://app.example.test/"));
        final var registration = new ClientRegistration(CLIENT_ID, "Name", true, List.of(), List.of(), List.of(),
                List.of(), true, List.of(), TTL, TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false, uris, false,
                false);
        uris.clear();
        final var withNull = new ArrayList<String>();
        withNull.add(null);

        assertEquals(List.of("https://app.example.test/"), registration.postLogoutRedirectUris());
        assertThrows(IllegalArgumentException.class, () -> new ClientRegistration(CLIENT_ID, "Name", true,
                List.of(), List.of(), List.of(), List.of(), true, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, null, false, false));
        assertThrows(IllegalArgumentException.class, () -> new ClientRegistration(CLIENT_ID, "Name", true,
                List.of(), List.of(), List.of(), List.of(), true, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, withNull, false, false));
    }

    /**
     * Verifies that the second-factor requirement is kept.
     */
    @Test
    void constructor_whenMfaRequiredIsGiven_keepsIt() {
        final var optional = create(CLIENT_ID, "Name", true, true, List.of(), TTL, TTL);
        final var required = new ClientRegistration(CLIENT_ID, "Name", true, List.of("none"),
                List.of("authorization_code"), List.of("http://localhost/cb"), List.of("openid"), true, List.of(), TTL,
                TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, true);

        assertFalse(optional.mfaRequired());
        assertTrue(required.mfaRequired());
    }
}
