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

package com.irurueta.authserver.authorization.infrastructure.persistence.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

/**
 * Unit tests of {@link RegisteredClientMapper}.
 */
class RegisteredClientMapperTest {

    /** Client id used by the tests. */
    private static final String CLIENT_ID = "bff";

    /** Internal identifier used by the tests. */
    private static final String ROW_ID = "row-id";

    /** Audience used by the tests. */
    private static final String AUDIENCE = "resource-server";

    /** Instant the client identifier was issued. */
    private static final Instant ISSUED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /** Lifetime of access tokens used by the tests. */
    private static final Duration ACCESS_TTL = Duration.ofMinutes(10);

    /** Lifetime of refresh tokens used by the tests. */
    private static final Duration REFRESH_TTL = Duration.ofHours(8);

    /** Mapper under test. */
    private final RegisteredClientMapper mapper = new RegisteredClientMapper();

    /**
     * Verifies that a registration is mapped with its identifiers, secret, collections, audiences as a custom
     * setting and token settings.
     */
    @Test
    void toRegisteredClient_whenRegistrationIsConfidential_mapsEveryField() {
        final var secret = encoded();

        final var client = mapper.toRegisteredClient(confidential(), ROW_ID, ISSUED_AT, secret);

        assertEquals(ROW_ID, client.getId());
        assertEquals(CLIENT_ID, client.getClientId());
        assertEquals(ISSUED_AT, client.getClientIdIssuedAt());
        assertEquals(secret, client.getClientSecret());
        assertEquals("Backend for Frontend", client.getClientName());
        assertEquals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), client.getClientAuthenticationMethods());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN),
                client.getAuthorizationGrantTypes());
        assertEquals(Set.of("openid", "profile"), client.getScopes());
        assertEquals(List.of(AUDIENCE),
                client.getClientSettings().getSetting(RegisteredClientMapper.AUDIENCES_SETTING));
        assertTrue(client.getClientSettings().isRequireProofKey());
        assertFalse(client.getClientSettings().isRequireAuthorizationConsent());
        assertEquals(ACCESS_TTL, client.getTokenSettings().getAccessTokenTimeToLive());
        assertEquals(REFRESH_TTL, client.getTokenSettings().getRefreshTokenTimeToLive());
        assertEquals(ClientRegistration.FORMAT_SELF_CONTAINED,
                client.getTokenSettings().getAccessTokenFormat().getValue());
        assertFalse(client.getTokenSettings().isReuseRefreshTokens());
    }

    /**
     * Verifies that a confidential registration survives the round trip unchanged.
     */
    @Test
    void toRegistration_whenClientWasMappedFromConfidentialRegistration_roundTrips() {
        final var registration = confidential();

        assertEquals(registration,
                mapper.toRegistration(mapper.toRegisteredClient(registration, ROW_ID, ISSUED_AT, encoded())));
    }

    /**
     * Verifies that a client authenticating with {@code none} is mapped as public and survives the round trip.
     */
    @Test
    void toRegistration_whenClientAuthenticatesWithNone_isNotConfidential() {
        final var registration = new ClientRegistration("spa", "Single-page application", false, List.of("none"),
                List.of("authorization_code"), List.of("http://localhost:3000/callback"), List.of("openid"), true,
                List.of(AUDIENCE), ACCESS_TTL, REFRESH_TTL, ClientRegistration.FORMAT_REFERENCE, true,
                List.of(), false, false);

        final var found = mapper.toRegistration(mapper.toRegisteredClient(registration, ROW_ID, ISSUED_AT, null));

        assertFalse(found.confidential());
        assertEquals(registration, found);
    }

    /**
     * Verifies that the collections, kept as sets by the framework, are returned sorted.
     */
    @Test
    void toRegistration_whenCollectionsAreUnordered_returnsThemSorted() {
        final var client = RegisteredClient.withId(ROW_ID).clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/b").redirectUri("http://localhost:8080/a")
                .scope("profile").scope("openid")
                .build();

        final var registration = mapper.toRegistration(client);

        assertEquals(List.of("client_secret_basic", "client_secret_post"), registration.authMethods());
        assertEquals(List.of("authorization_code", "refresh_token"), registration.grantTypes());
        assertEquals(List.of("http://localhost:8080/a", "http://localhost:8080/b"), registration.redirectUris());
        assertEquals(List.of("openid", "profile"), registration.scopes());
    }

    /**
     * Verifies that a client without the audiences setting is given its own client id as audience.
     */
    @Test
    void toRegistration_whenAudiencesSettingIsAbsent_defaultsToClientId() {
        final var client = RegisteredClient.withId(ROW_ID).clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        assertEquals(List.of(CLIENT_ID), mapper.toRegistration(client).audiences());
    }

    /**
     * Verifies that the audiences setting is read as a list of strings.
     */
    @Test
    void audiencesOf_whenSettingIsAList_returnsItsValues() {
        final var settings = ClientSettings.builder()
                .setting(RegisteredClientMapper.AUDIENCES_SETTING, List.of(AUDIENCE, CLIENT_ID)).build();

        assertEquals(List.of(AUDIENCE, CLIENT_ID), mapper.audiencesOf(settings));
    }

    /**
     * Verifies that a missing setting gives no audiences.
     */
    @Test
    void audiencesOf_whenSettingIsAbsent_returnsEmpty() {
        assertTrue(mapper.audiencesOf(ClientSettings.builder().build()).isEmpty());
    }

    /**
     * Verifies that a setting that is not a list is ignored.
     */
    @Test
    void audiencesOf_whenSettingIsNotAList_returnsEmpty() {
        final var settings = ClientSettings.builder().setting(RegisteredClientMapper.AUDIENCES_SETTING, AUDIENCE)
                .build();

        assertTrue(mapper.audiencesOf(settings).isEmpty());
    }

    /**
     * Builds a runtime-generated placeholder for an encoded value.
     *
     * @return the placeholder.
     */
    private static String encoded() {
        return "encoded-" + UUID.randomUUID();
    }

    /**
     * Builds a confidential registration with refresh tokens and rotation.
     *
     * @return the registration.
     */
    private static ClientRegistration confidential() {
        return new ClientRegistration(CLIENT_ID, "Backend for Frontend", true, List.of("client_secret_basic"),
                List.of("authorization_code", "refresh_token"), List.of("http://localhost:8080/login/oauth2/code/bff"),
                List.of("openid", "profile"), true, List.of(AUDIENCE), ACCESS_TTL, REFRESH_TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false);
    }

    /**
     * Verifies that the post-logout redirect URIs are mapped both ways, sorted.
     */
    @Test
    void toRegisteredClient_whenPostLogoutRedirectUrisAreGiven_mapsThemBothWays() {
        final var base = confidential();
        final var registration = new ClientRegistration(base.clientId(), base.name(), base.confidential(),
                base.authMethods(), base.grantTypes(), base.redirectUris(), base.scopes(), base.requireProofKey(),
                base.audiences(), base.accessTokenTtl(), base.refreshTokenTtl(), base.accessTokenFormat(),
                base.reuseRefreshTokens(), List.of("http://localhost:8080/b", "http://localhost:8080/a"), false, false);

        final var client = mapper.toRegisteredClient(registration, ROW_ID, ISSUED_AT, encoded());

        assertTrue(client.getPostLogoutRedirectUris().contains("http://localhost:8080/a"));
        assertEquals(List.of("http://localhost:8080/a", "http://localhost:8080/b"),
                mapper.toRegistration(client).postLogoutRedirectUris());
    }

    /**
     * Verifies that the consent requirement is mapped both ways.
     */
    @Test
    void toRegisteredClient_whenConsentIsRequired_mapsItBothWays() {
        final var base = confidential();
        final var registration = new ClientRegistration(base.clientId(), base.name(), base.confidential(),
                base.authMethods(), base.grantTypes(), base.redirectUris(), base.scopes(), base.requireProofKey(),
                base.audiences(), base.accessTokenTtl(), base.refreshTokenTtl(), base.accessTokenFormat(),
                base.reuseRefreshTokens(), base.postLogoutRedirectUris(), true, false);

        final var client = mapper.toRegisteredClient(registration, ROW_ID, ISSUED_AT, encoded());

        assertTrue(client.getClientSettings().isRequireAuthorizationConsent());
        assertTrue(mapper.toRegistration(client).requireConsent());
        assertFalse(mapper.toRegistration(
                mapper.toRegisteredClient(base, ROW_ID, ISSUED_AT, encoded())).requireConsent());
    }

    /**
     * Verifies that the second-factor requirement is mapped both ways, off by default.
     */
    @Test
    void toRegisteredClient_whenMfaIsRequired_mapsItBothWays() {
        final var base = confidential();
        final var registration = new ClientRegistration(base.clientId(), base.name(), base.confidential(),
                base.authMethods(), base.grantTypes(), base.redirectUris(), base.scopes(), base.requireProofKey(),
                base.audiences(), base.accessTokenTtl(), base.refreshTokenTtl(), base.accessTokenFormat(),
                base.reuseRefreshTokens(), base.postLogoutRedirectUris(), false, true);

        final var client = mapper.toRegisteredClient(registration, ROW_ID, ISSUED_AT, encoded());

        assertEquals(Boolean.TRUE, client.getClientSettings().getSetting(RegisteredClientMapper.MFA_REQUIRED_SETTING));
        assertTrue(mapper.toRegistration(client).mfaRequired());
        assertFalse(mapper.toRegistration(
                mapper.toRegisteredClient(base, ROW_ID, ISSUED_AT, encoded())).mfaRequired());
    }

    /**
     * Verifies that a client without the setting does not require a second factor.
     */
    @Test
    void mfaRequiredOf_whenSettingIsAbsent_returnsFalse() {
        assertFalse(mapper.mfaRequiredOf(ClientSettings.builder().build()));
    }
}
