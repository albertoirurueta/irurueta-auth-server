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
                false, null, null, null, null, false));
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
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false,
                null, null, null, null, false));
        assertThrows(IllegalArgumentException.class, () -> new ClientRegistration(CLIENT_ID, "Name", true,
                List.of(), List.of(), List.of(), withNull, true, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false,
                null, null, null, null, false));
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
     * Verifies that a public client whose only grant type is implicit may skip PKCE.
     */
    @Test
    void constructor_whenOnlyGrantIsImplicit_allowsPublicClientWithoutPkce() {
        final var client = implicit(false, false, List.of("implicit"), true);

        assertFalse(client.requireProofKey());
        assertEquals(List.of("implicit"), client.grantTypes());
    }

    /**
     * Verifies that the PKCE exemption does not extend to a client with other grants next to implicit.
     */
    @Test
    void constructor_whenImplicitIsMixedWithOtherGrantAndNoPkce_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> implicit(false, false, List.of("implicit", "authorization_code"), true));
    }

    /**
     * Verifies that an implicit client cannot require consent.
     */
    @Test
    void constructor_whenImplicitRequiresConsent_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> implicit(true, false, List.of("implicit"), true));
    }

    /**
     * Verifies that an implicit client cannot have refresh tokens.
     */
    @Test
    void constructor_whenImplicitHasRefreshToken_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> implicit(false, false, List.of("implicit", "refresh_token"), true));
    }

    /**
     * Verifies that an implicit client cannot be confidential.
     */
    @Test
    void constructor_whenImplicitIsConfidential_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> implicit(false, true, List.of("implicit"), true));
    }

    /**
     * Verifies that a tls_client_auth client needs a subject DN.
     */
    @Test
    void constructor_whenTlsClientAuthHasNoSubjectDn_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> authClient("tls_client_auth", null, null, null));
        assertEquals("CN=client",
                authClient("tls_client_auth", null, null, "CN=client").tlsClientAuthSubjectDn());
    }

    /**
     * Verifies that private_key_jwt and self_signed_tls_client_auth need a JWK set or a JWK set URL.
     */
    @Test
    void constructor_whenKeyBasedMethodHasNoKeys_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> authClient("private_key_jwt", null, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> authClient("self_signed_tls_client_auth", null, null, null));
        assertEquals("{\"keys\":[]}", authClient("self_signed_tls_client_auth", null, "{\"keys\":[]}", null).jwks());
        assertEquals("https://c.example.test/jwks",
                authClient("self_signed_tls_client_auth", "https://c.example.test/jwks", null, null).jwkSetUrl());
    }

    /**
     * Verifies that a blank optional text is rejected.
     */
    @Test
    void constructor_whenOptionalTextIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> authClient("client_secret_basic", " ", null, null));
        assertThrows(IllegalArgumentException.class, () -> authClient("client_secret_basic", null, "", null));
    }

    /**
     * Verifies which authentication methods count as using a client secret.
     */
    @Test
    void usesClientSecret_whenMethodsVary_matchesClientSecretMethodsOnly() {
        assertTrue(authClient("client_secret_basic", null, null, null).usesClientSecret());
        assertTrue(authClient("client_secret_post", null, null, null).usesClientSecret());
        assertFalse(authClient("none", null, null, null).usesClientSecret());
        assertFalse(authClient("private_key_jwt", "https://c.example.test/jwks", null, null).usesClientSecret());
    }

    /**
     * Verifies that a private_key_jwt client with registered keys needs the algorithm its assertions are signed with.
     */
    @Test
    void constructor_whenPrivateKeyJwtHasJwksAndNoAlgorithm_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> authClient("private_key_jwt", null, "{\"keys\":[]}", null));
        assertEquals("ES256", new ClientRegistration(CLIENT_ID, "Name", true, List.of("private_key_jwt"),
                List.of("client_credentials"), List.of(), List.of("api"), true, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false, null, "{\"keys\":[]}",
                "ES256", null, false).tokenEndpointSigningAlgorithm());
    }

    /**
     * Verifies that only a client with the implicit grant type reports using it.
     */
    @Test
    void usesImplicit_whenGrantTypesVary_matchesImplicitOnly() {
        assertTrue(implicit(false, false, List.of("implicit"), true).usesImplicit());
        assertFalse(authClient("client_secret_basic", null, null, null).usesImplicit());
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
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false,
                null, null, null, null, false);
    }

    /**
     * Verifies that post-logout redirect URIs are copied and that a null list or a null element is rejected.
     */
    @Test
    void constructor_whenPostLogoutRedirectUrisAreGiven_copiesThemAndRejectsNulls() {
        final var uris = new ArrayList<>(List.of("https://app.example.test/"));
        final var registration = new ClientRegistration(CLIENT_ID, "Name", true, List.of(), List.of(), List.of(),
                List.of(), true, List.of(), TTL, TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false, uris, false,
                false, null, null, null, null, false);
        uris.clear();
        final var withNull = new ArrayList<String>();
        withNull.add(null);

        assertEquals(List.of("https://app.example.test/"), registration.postLogoutRedirectUris());
        assertThrows(IllegalArgumentException.class, () -> new ClientRegistration(CLIENT_ID, "Name", true,
                List.of(), List.of(), List.of(), List.of(), true, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, null, false, false, null, null, null, null, false));
        assertThrows(IllegalArgumentException.class, () -> new ClientRegistration(CLIENT_ID, "Name", true,
                List.of(), List.of(), List.of(), List.of(), true, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, withNull, false, false,
                null, null, null, null, false));
    }

    /**
     * Verifies that the second-factor requirement is kept.
     */
    @Test
    void constructor_whenMfaRequiredIsGiven_keepsIt() {
        final var optional = create(CLIENT_ID, "Name", true, true, List.of(), TTL, TTL);
        final var required = new ClientRegistration(CLIENT_ID, "Name", true, List.of("none"),
                List.of("authorization_code"), List.of("http://localhost/cb"), List.of("openid"), true, List.of(), TTL,
                TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, true,
                null, null, null, null, false);

        assertFalse(optional.mfaRequired());
        assertTrue(required.mfaRequired());
    }

    /**
     * Creates an implicit-flow registration.
     *
     * @param consent      whether consent is required.
     * @param confidential whether the client is confidential.
     * @param grantTypes   the grant types.
     * @param noPkce       {@code true} to not require PKCE.
     * @return the registration.
     */
    private static ClientRegistration implicit(
            final boolean consent, final boolean confidential, final List<String> grantTypes, final boolean noPkce) {
        return new ClientRegistration(CLIENT_ID, "Name", confidential,
                List.of(confidential ? "client_secret_basic" : "none"), grantTypes, List.of("http://localhost/cb"), List.of("openid"), !noPkce, List.of(), TTL, TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), consent, false,
                null, null, null, null, false);
    }

    /**
     * Creates a registration with one authentication method and the given key settings.
     *
     * @param method     the authentication method.
     * @param jwkSetUrl  the JWK set URL, or {@code null}.
     * @param jwks       the JWK set, or {@code null}.
     * @param subjectDn  the TLS subject DN, or {@code null}.
     * @return the registration.
     */
    private static ClientRegistration authClient(
            final String method, final String jwkSetUrl, final String jwks, final String subjectDn) {
        return new ClientRegistration(CLIENT_ID, "Name", true, List.of(method), List.of("client_credentials"),
                List.of(), List.of("api"), true, List.of(), TTL, TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false,
                List.of(), false, false, jwkSetUrl, jwks, null, subjectDn, false);
    }
}
