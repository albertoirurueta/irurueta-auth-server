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

package com.irurueta.authserver.authorization.api.web.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientRequest}.
 */
class ClientRequestTest {

    /** Client identifier used by the tests. */
    private static final String CLIENT_ID = "app";

    /** Access token lifetime used by the tests. */
    private static final Duration ACCESS_TTL = Duration.ofMinutes(5);

    /** Refresh token lifetime used by the tests. */
    private static final Duration REFRESH_TTL = Duration.ofHours(1);

    /**
     * The constructor copies the lists so later changes of the source do not leak in.
     */
    @Test
    void constructor_whenListIsMutated_keepsOriginalValues() {
        final var scopes = new ArrayList<>(List.of("openid"));
        final var request = request(scopes, List.of("a"), null);

        scopes.add("profile");

        assertEquals(List.of("openid"), request.scopes());
    }

    /**
     * Absent audiences and format fall back to the registration defaults.
     */
    @Test
    void toRegistration_whenOptionalFieldsAreMissing_usesDefaults() {
        final var registration = request(List.of("openid"), null, null).toRegistration();

        assertEquals(List.of(CLIENT_ID), registration.audiences());
        assertEquals(ClientRegistration.FORMAT_SELF_CONTAINED, registration.accessTokenFormat());
    }

    /**
     * A blank format falls back to self-contained too.
     */
    @Test
    void toRegistration_whenFormatIsBlank_usesSelfContained() {
        final var registration = request(List.of("openid"), List.of("api"), " ").toRegistration();

        assertEquals(List.of("api"), registration.audiences());
        assertEquals(ClientRegistration.FORMAT_SELF_CONTAINED, registration.accessTokenFormat());
    }

    /**
     * An explicit format is kept.
     */
    @Test
    void toRegistration_whenFormatIsGiven_keepsIt() {
        final var registration = request(List.of("openid"), null, ClientRegistration.FORMAT_REFERENCE)
                .toRegistration();

        assertEquals(ClientRegistration.FORMAT_REFERENCE, registration.accessTokenFormat());
    }

    /**
     * An invalid registration is rejected with an illegal argument.
     */
    @Test
    void toRegistration_whenListIsNull_throwsIllegalArgumentException() {
        final var request = request(null, null, null);

        assertThrows(IllegalArgumentException.class, request::toRegistration);
    }

    /**
     * Builds a confidential request.
     *
     * @param scopes   scopes.
     * @param audience audiences.
     * @param format   access token format.
     * @return the request.
     */
    private static ClientRequest request(final List<String> scopes, final List<String> audience, final String format) {
        return new ClientRequest(CLIENT_ID, "App", true, List.of("client_secret_basic"),
                List.of("authorization_code"), List.of("http://localhost/cb"), scopes, true, audience, ACCESS_TTL,
                REFRESH_TTL, format, false);
    }
}
