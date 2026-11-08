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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Unit tests of {@link ClientRegistrationMapper}.
 */
class ClientRegistrationMapperTest {

    /** Client id of the tests. */
    private static final String CLIENT_ID = "client-id";

    /** Secret of the tests, never a real one. */
    private static final String SECRET = "not-a-secret";

    /** Tenant id used by the tests. */
    private static final String TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad";

    /** Mapper under test. */
    private final ClientRegistrationMapper mapper = new ClientRegistrationMapper();

    /**
     * Verifies that one registration per enabled provider is built, in enum order, and none for a disabled one.
     */
    @Test
    void toRegistrations_whenSomeProvidersAreEnabled_buildsOneRegistrationEach() {
        final var properties = new SocialProperties(Map.of(
                "github", provider(CLIENT_ID, SECRET),
                "google", provider(CLIENT_ID, SECRET),
                "apple", provider("", null)));

        final var registrations = mapper.toRegistrations(properties);

        assertEquals(List.of("google", "github"),
                registrations.stream().map(ClientRegistration::getRegistrationId).toList());
        assertTrue(mapper.toRegistrations(new SocialProperties(Map.of())).isEmpty());
    }

    /**
     * Verifies the Google registration: the framework's defaults with the configured client.
     */
    @Test
    void toRegistration_whenGoogle_usesTheFrameworkDefaultsWithTheConfiguredClient() {
        final var registration = mapper.toRegistration(IdentityProvider.GOOGLE, provider(CLIENT_ID, SECRET));

        assertEquals(CLIENT_ID, registration.getClientId());
        assertEquals(SECRET, registration.getClientSecret());
        assertEquals("https://accounts.google.com", registration.getProviderDetails().getIssuerUri());
        assertTrue(registration.getScopes().contains("openid"));
        assertTrue(registration.getScopes().contains("email"));
    }

    /**
     * Verifies the GitHub registration: plain OAuth 2.0 with the scope of the e-mail addresses and the numeric id as
     * the name attribute.
     */
    @Test
    void toRegistration_whenGitHub_isPlainOAuth2WithTheEmailScope() {
        final var registration = mapper.toRegistration(IdentityProvider.GITHUB, provider(CLIENT_ID, SECRET));

        assertEquals("id", registration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
        assertTrue(registration.getScopes().contains("user:email"));
        assertTrue(registration.getScopes().contains("read:user"));
        assertFalse(registration.getScopes().contains("openid"));
        assertNull(registration.getProviderDetails().getIssuerUri());
    }

    /**
     * Verifies that the Microsoft registration has the endpoints of its tenant and no issuer, which the multi-tenant
     * validator replaces.
     */
    @Test
    void toRegistration_whenMicrosoft_hasTheTenantEndpointsAndNoIssuer() {
        final var settings = new SocialProperties.Provider(CLIENT_ID, SECRET, false, TENANT_ID, null, null, null,
                null, null);

        final var registration = mapper.toRegistration(IdentityProvider.MICROSOFT, settings);

        assertNull(registration.getProviderDetails().getIssuerUri());
        assertEquals("https://login.microsoftonline.com/" + TENANT_ID + "/oauth2/v2.0/authorize",
                registration.getProviderDetails().getAuthorizationUri());
        assertEquals("https://login.microsoftonline.com/" + TENANT_ID + "/oauth2/v2.0/token",
                registration.getProviderDetails().getTokenUri());
        assertEquals("https://login.microsoftonline.com/" + TENANT_ID + "/discovery/v2.0/keys",
                registration.getProviderDetails().getJwkSetUri());
        assertEquals(ClientRegistrationMapper.MICROSOFT_USER_INFO_URI,
                registration.getProviderDetails().getUserInfoEndpoint().getUri());
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, registration.getClientAuthenticationMethod());
        assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, registration.getAuthorizationGrantType());
    }

    /**
     * Verifies that the Apple registration has no secret of its own, posts the client authentication and asks for the
     * name and e-mail scopes.
     */
    @Test
    void toRegistration_whenApple_hasNoSecretAndPostsTheClientAuthentication() {
        final var settings = new SocialProperties.Provider(CLIENT_ID, null, false, null, null, "team", "key", "pem",
                null);

        final var registration = mapper.toRegistration(IdentityProvider.APPLE, settings);

        assertEquals("", registration.getClientSecret());
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, registration.getClientAuthenticationMethod());
        assertEquals("https://appleid.apple.com", registration.getProviderDetails().getIssuerUri());
        assertEquals("https://appleid.apple.com/auth/keys", registration.getProviderDetails().getJwkSetUri());
        assertTrue(registration.getScopes().containsAll(List.of("openid", "name", "email")));
        assertEquals(ClientRegistrationMapper.REDIRECT_URI, registration.getRedirectUri());
    }

    /**
     * Builds a provider that needs a client secret.
     *
     * @param clientId client id.
     * @param secret   client secret.
     * @return the provider.
     */
    private static SocialProperties.Provider provider(final String clientId, final String secret) {
        return new SocialProperties.Provider(clientId, secret, false, null, null, null, null, null, null);
    }
}
