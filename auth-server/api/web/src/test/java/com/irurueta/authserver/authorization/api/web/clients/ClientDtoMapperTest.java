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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.api.web.v1.generated.model.ClientRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ClientResponse;
import com.irurueta.authserver.authorization.application.clients.CreatedClient;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientDtoMapper}.
 */
class ClientDtoMapperTest {

    /** Lifetime of the access tokens of the test clients, in minutes. */
    private static final long ACCESS_MINUTES = 5;

    /** Lifetime of the refresh tokens of the test clients, in hours. */
    private static final long REFRESH_HOURS = 1;

    /** Redirect URI of the test clients. */
    private static final String REDIRECT_URI = "https://app.example.test/callback";

    /** Mapper under test. */
    private final ClientDtoMapper mapper = new ClientDtoMapper();

    /**
     * Verifies that every field of a complete request reaches the registration.
     */
    @Test
    void toRegistration_whenRequestIsComplete_copiesEveryField() {
        final var request = new ClientRequest("app", "App", true, List.of("client_secret_basic"),
                List.of("authorization_code"), List.of(REDIRECT_URI), List.of("openid"), true, List.of("api"),
                Duration.ofMinutes(ACCESS_MINUTES), Duration.ofHours(REFRESH_HOURS),
                ClientRegistration.FORMAT_REFERENCE, true);

        final var registration = mapper.toRegistration(request);

        assertEquals(new ClientRegistration("app", "App", true, List.of("client_secret_basic"),
                List.of("authorization_code"), List.of(REDIRECT_URI), List.of("openid"), true, List.of("api"),
                Duration.ofMinutes(ACCESS_MINUTES), Duration.ofHours(REFRESH_HOURS),
                ClientRegistration.FORMAT_REFERENCE, true), registration);
    }

    /**
     * Verifies the defaults of the optional fields: flags off, the client identifier as audience and self-contained
     * tokens.
     */
    @Test
    void toRegistration_whenOptionalFieldsAreAbsent_appliesDefaults() {
        final var request = new ClientRequest("app", "App", true, List.of("client_secret_basic"),
                List.of("client_credentials"), List.of(), List.of("api.read"), null, null,
                Duration.ofMinutes(ACCESS_MINUTES), Duration.ofHours(REFRESH_HOURS), null, null);

        final var registration = mapper.toRegistration(request);

        assertFalse(registration.requireProofKey());
        assertFalse(registration.reuseRefreshTokens());
        assertEquals(List.of("app"), registration.audiences());
        assertEquals(ClientRegistration.FORMAT_SELF_CONTAINED, registration.accessTokenFormat());
    }

    /**
     * Verifies that a blank format means self-contained tokens.
     */
    @Test
    void toRegistration_whenFormatIsBlank_usesSelfContainedTokens() {
        final var request = new ClientRequest("app", "App", true, List.of("client_secret_basic"),
                List.of("client_credentials"), List.of(), List.of("api.read"), false, List.of(),
                Duration.ofMinutes(ACCESS_MINUTES), Duration.ofHours(REFRESH_HOURS), " ", false);

        assertEquals(ClientRegistration.FORMAT_SELF_CONTAINED, mapper.toRegistration(request).accessTokenFormat());
    }

    /**
     * Verifies that a definition the domain rejects fails with the domain's exception, which the exception handler
     * answers as a 400 problem.
     */
    @Test
    void toRegistration_whenPublicClientSkipsPkce_throwsIllegalArgumentException() {
        final var request = new ClientRequest("spa", "SPA", false, List.of("none"),
                List.of("authorization_code"), List.of(REDIRECT_URI), List.of("openid"), false, null,
                Duration.ofMinutes(ACCESS_MINUTES), Duration.ofHours(REFRESH_HOURS), null, false);

        assertThrows(IllegalArgumentException.class, () -> mapper.toRegistration(request));
    }

    /**
     * Verifies that every field of the registration reaches its public view.
     */
    @Test
    void toResponse_whenRegistrationIsGiven_copiesEveryField() {
        final var registration = registration();

        final var response = mapper.toResponse(registration);

        assertEquals(registration.clientId(), response.clientId());
        assertEquals(registration.name(), response.name());
        assertTrue(response.confidential());
        assertEquals(registration.authMethods(), response.authMethods());
        assertEquals(registration.grantTypes(), response.grantTypes());
        assertEquals(registration.redirectUris(), response.redirectUris());
        assertEquals(registration.scopes(), response.scopes());
        assertTrue(response.requireProofKey());
        assertEquals(registration.audiences(), response.audiences());
        assertEquals(registration.accessTokenTtl(), response.accessTokenTtl());
        assertEquals(registration.refreshTokenTtl(), response.refreshTokenTtl());
        assertEquals(registration.accessTokenFormat(), response.accessTokenFormat());
        assertFalse(response.reuseRefreshTokens());
    }

    /**
     * Verifies that several registrations keep their order.
     */
    @Test
    void toResponses_whenRegistrationsAreGiven_keepsTheirOrder() {
        final var first = registration();

        final var responses = mapper.toResponses(List.of(first, publicClient()));

        assertEquals(List.of("app", "spa"), responses.stream().map(ClientResponse::clientId).toList());
    }

    /**
     * Verifies that the created client carries its secret once, and that the secret never reaches a log.
     */
    @Test
    void toCreatedResponse_whenClientIsConfidential_carriesTheSecretButHidesItFromToString() {
        final var secret = UUID.randomUUID().toString();

        final var response = mapper.toCreatedResponse(new CreatedClient(registration(), secret));

        assertEquals("app", response.client().clientId());
        assertEquals(secret, response.clientSecret());
        assertFalse(response.toString().contains(secret));
    }

    /**
     * Verifies that a public client is created without a secret.
     */
    @Test
    void toCreatedResponse_whenClientIsPublic_hasNoSecret() {
        assertNull(mapper.toCreatedResponse(new CreatedClient(publicClient(), null)).clientSecret());
    }

    /**
     * Verifies that a rotated secret is answered, and that it never reaches a log.
     */
    @Test
    void toSecretResponse_whenSecretIsGiven_carriesItButHidesItFromToString() {
        final var secret = UUID.randomUUID().toString();

        final var response = mapper.toSecretResponse(secret);

        assertEquals(secret, response.clientSecret());
        assertFalse(response.toString().contains(secret));
    }

    /**
     * Builds a confidential client.
     *
     * @return the registration.
     */
    private static ClientRegistration registration() {
        return new ClientRegistration("app", "App", true, List.of("client_secret_basic"),
                List.of("authorization_code", "refresh_token"), List.of(REDIRECT_URI), List.of("openid"), true,
                List.of("api"), Duration.ofMinutes(ACCESS_MINUTES), Duration.ofHours(REFRESH_HOURS),
                ClientRegistration.FORMAT_SELF_CONTAINED, false);
    }

    /**
     * Builds a public client.
     *
     * @return the registration.
     */
    private static ClientRegistration publicClient() {
        return new ClientRegistration("spa", "SPA", false, List.of("none"), List.of("authorization_code"),
                List.of(REDIRECT_URI), List.of("openid"), true, List.of(), Duration.ofMinutes(ACCESS_MINUTES),
                Duration.ofHours(REFRESH_HOURS), ClientRegistration.FORMAT_SELF_CONTAINED, false);
    }
}
