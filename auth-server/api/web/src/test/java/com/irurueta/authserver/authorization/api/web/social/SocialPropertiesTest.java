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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SocialProperties} and its {@link SocialProperties.Provider}.
 */
class SocialPropertiesTest {

    /** Tenant id used by the tests. */
    private static final String TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad";

    /** Name of the settings of the tests. */
    private static final String CLIENT = "client";

    /** Secret of the tests, never a real one. */
    private static final String SECRET = "not-a-secret";

    /**
     * Verifies that a provider with a client id and a secret is enabled and the others are not.
     */
    @Test
    void enabledProviders_whenOnlySomeHaveAClientId_listsOnlyThoseInEnumOrder() {
        final var properties = new SocialProperties(Map.of(
                "github", provider(CLIENT, SECRET),
                "google", provider(CLIENT, SECRET),
                "microsoft", provider("", "")));

        assertEquals(List.of(IdentityProvider.GOOGLE, IdentityProvider.GITHUB),
                List.copyOf(properties.enabledProviders().keySet()));
        assertTrue(properties.find(IdentityProvider.GOOGLE).isPresent());
        assertTrue(properties.find(IdentityProvider.MICROSOFT).isEmpty());
    }

    /**
     * Verifies that no settings at all is valid and enables nothing.
     */
    @Test
    void constructor_whenProvidersAreMissing_enablesNothing() {
        assertTrue(new SocialProperties(null).enabledProviders().isEmpty());
    }

    /**
     * Verifies that a provider setting that is {@code null} is ignored.
     */
    @Test
    void constructor_whenAProviderIsNull_ignoresIt() {
        final var providers = new HashMap<String, SocialProperties.Provider>();
        providers.put("google", null);

        assertTrue(new SocialProperties(providers).providers().isEmpty());
    }

    /**
     * Verifies that an unknown provider id is refused.
     */
    @Test
    void constructor_whenProviderIsUnknown_throwsIllegalArgumentException() {
        final var providers = Map.of("facebook", provider(CLIENT, SECRET));

        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(providers));
    }

    /**
     * Verifies that an enabled provider without a secret is refused.
     */
    @Test
    void constructor_whenEnabledProviderHasNoSecret_throwsIllegalArgumentException() {
        final var providers = Map.of("google", provider(CLIENT, " "));

        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(providers));
    }

    /**
     * Verifies that an enabled Apple provider needs its key settings, not a secret.
     */
    @Test
    void constructor_whenAppleLacksItsKeySettings_throwsIllegalArgumentException() {
        final var withoutTeam = Map.of("apple", apple("", "key", "pem", Duration.ofMinutes(1)));
        final var withoutKeyId = Map.of("apple", apple("team", "", "pem", Duration.ofMinutes(1)));
        final var withoutKey = Map.of("apple", apple("team", "key", "", Duration.ofMinutes(1)));

        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(withoutTeam));
        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(withoutKeyId));
        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(withoutKey));
    }

    /**
     * Verifies that the lifetime of the Apple client secret must be positive and at most six months.
     */
    @Test
    void constructor_whenAppleSecretLifetimeIsOutOfRange_throwsIllegalArgumentException() {
        final var zero = Map.of("apple", apple("team", "key", "pem", Duration.ZERO));
        final var negative = Map.of("apple", apple("team", "key", "pem", Duration.ofSeconds(-1)));
        final var tooLong = Map.of("apple", apple("team", "key", "pem",
                SocialProperties.MAX_APPLE_CLIENT_SECRET_TTL.plusSeconds(1)));

        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(zero));
        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(negative));
        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(tooLong));
        assertTrue(new SocialProperties(Map.of("apple", apple("team", "key", "pem",
                SocialProperties.MAX_APPLE_CLIENT_SECRET_TTL))).find(IdentityProvider.APPLE).isPresent());
    }

    /**
     * Verifies that a tenant that cannot be part of a URL is refused.
     */
    @Test
    void constructor_whenMicrosoftTenantIsInvalid_throwsIllegalArgumentException() {
        final var badTenant = Map.of("microsoft", microsoft("a/b", List.of()));
        final var badAllowed = Map.of("microsoft", microsoft("common", List.of("ok", "../x")));

        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(badTenant));
        assertThrows(IllegalArgumentException.class, () -> new SocialProperties(badAllowed));
    }

    /**
     * Verifies that a disabled provider is not validated: its other settings may be empty.
     */
    @Test
    void constructor_whenProviderIsDisabled_doesNotValidateIt() {
        final var disabledMicrosoft = new SocialProperties.Provider("", "", false, "a/b", List.of(), null, null, null,
                null);
        final var disabledApple = new SocialProperties.Provider("", "", false, null, null, "", "", "", Duration.ZERO);

        assertTrue(new SocialProperties(Map.of("microsoft", disabledMicrosoft, "apple", disabledApple))
                .enabledProviders().isEmpty());
    }

    /**
     * Verifies the defaults the provider record fills in.
     */
    @Test
    void providerConstructor_whenSettingsAreMissing_fillsTheDefaults() {
        final var provider = new SocialProperties.Provider(CLIENT, SECRET, false, " ", null, null, null, null, null);

        assertEquals(SocialProperties.COMMON_TENANT, provider.tenant());
        assertTrue(provider.allowedTenants().isEmpty());
        assertEquals(SocialProperties.DEFAULT_APPLE_CLIENT_SECRET_TTL, provider.clientSecretTtl());
    }

    /**
     * Verifies that the permitted tenants are the configured ones, else the tenant id, else none.
     */
    @Test
    void permittedTenants_whenAsked_prefersTheListThenTheTenantIdThenNone() {
        assertEquals(List.of("a"), microsoft("common", List.of("a")).permittedTenants());
        assertEquals(List.of(TENANT_ID), microsoft(TENANT_ID, List.of()).permittedTenants());
        assertTrue(microsoft("common", List.of()).permittedTenants().isEmpty());
        assertTrue(microsoft("contoso.com", List.of()).permittedTenants().isEmpty());
    }

    /**
     * Verifies the trust of a provider: off by default and when the provider is not enabled.
     */
    @Test
    void trust_whenAsked_isOnlyTrueForAnEnabledTrustedProvider() {
        final var trusted = new SocialProperties.Provider(CLIENT, SECRET, true, null, null, null, null, null, null);
        final var properties = new SocialProperties(Map.of("google", trusted, "github", provider(CLIENT, SECRET)));

        assertTrue(properties.trust(IdentityProvider.GOOGLE).trustMfa());
        assertFalse(properties.trust(IdentityProvider.GITHUB).trustMfa());
        assertFalse(properties.trust(IdentityProvider.APPLE).trustMfa());
        assertEquals(IdentityProvider.APPLE, properties.trust(IdentityProvider.APPLE).provider());
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

    /**
     * Builds an enabled Apple provider.
     *
     * @param teamId team id.
     * @param keyId  key id.
     * @param key    private key.
     * @param ttl    lifetime of the secret.
     * @return the provider.
     */
    private static SocialProperties.Provider apple(
            final String teamId, final String keyId, final String key, final Duration ttl) {
        return new SocialProperties.Provider(CLIENT, null, false, null, null, teamId, keyId, key, ttl);
    }

    /**
     * Builds an enabled Microsoft provider.
     *
     * @param tenant  tenant.
     * @param allowed allowed tenants.
     * @return the provider.
     */
    private static SocialProperties.Provider microsoft(final String tenant, final List<String> allowed) {
        return new SocialProperties.Provider(CLIENT, SECRET, false, tenant, allowed, null, null, null, null);
    }
}
