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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Unit tests of {@link IdTokenValidatorFactory}.
 */
class IdTokenValidatorFactoryTest {

    /** Client id of the tests. */
    private static final String CLIENT_ID = "client-id";

    /** Secret of the tests, never a real one. */
    private static final String SECRET = "not-a-secret";

    /** Tenant of the tokens. */
    private static final String TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";

    /** Lifetime of the test tokens, in seconds. */
    private static final long LIFETIME_SECONDS = 600L;

    /** Maps settings onto registrations. */
    private final ClientRegistrationMapper mapper = new ClientRegistrationMapper();

    /**
     * Verifies that a Microsoft token of any tenant is accepted when no tenant is required, the issuer being the one of
     * its tenant, and refused when the issuer is another's.
     */
    @Test
    void apply_whenMicrosoft_checksTheIssuerAgainstTheTenantOfTheToken() {
        final var factory = factory(new SocialProperties.Provider(CLIENT_ID, SECRET, false, null, null, null, null,
                null, null));
        final var validator = factory.apply(registration(IdentityProvider.MICROSOFT));
        final var own = "https://login.microsoftonline.com/" + TENANT + "/v2.0";

        assertFalse(validator.validate(token(own, TENANT)).hasErrors());
        assertTrue(validator.validate(token("https://login.microsoftonline.com/x/v2.0", TENANT)).hasErrors());
    }

    /**
     * Verifies that Microsoft is limited to the configured tenants.
     */
    @Test
    void apply_whenMicrosoftHasAllowedTenants_refusesOthers() {
        final var factory = factory(new SocialProperties.Provider(CLIENT_ID, SECRET, false, null, List.of("other"),
                null, null, null, null));
        final var validator = factory.apply(registration(IdentityProvider.MICROSOFT));

        assertTrue(validator.validate(
                token("https://login.microsoftonline.com/" + TENANT + "/v2.0", TENANT)).hasErrors());
    }

    /**
     * Verifies that another provider gets the framework's validator, which compares the issuer with the registration.
     */
    @Test
    void apply_whenGoogle_usesTheFrameworkValidator() {
        final var factory = factory(new SocialProperties.Provider(CLIENT_ID, SECRET, false, null, null, null, null,
                null, null));
        final var validator = factory.apply(registration(IdentityProvider.GOOGLE));

        assertTrue(validator.validate(token("https://evil.example", TENANT)).hasErrors());
    }

    /**
     * Builds the factory with one provider enabled under each of the ids the tests use.
     *
     * @param settings settings of the provider.
     * @return the factory.
     */
    private static IdTokenValidatorFactory factory(final SocialProperties.Provider settings) {
        return new IdTokenValidatorFactory(new SocialProperties(Map.of("microsoft", settings, "google", settings)));
    }

    /**
     * Builds the registration of a provider.
     *
     * @param provider the provider.
     * @return the registration.
     */
    private ClientRegistration registration(final IdentityProvider provider) {
        return mapper.toRegistration(provider,
                new SocialProperties.Provider(CLIENT_ID, SECRET, false, null, null, null, null, null, null));
    }

    /**
     * Builds an ID token.
     *
     * @param issuer issuer.
     * @param tenant tenant.
     * @return the token.
     */
    private static Jwt token(final String issuer, final String tenant) {
        return Jwt.withTokenValue("token").header("alg", "RS256").subject("sub")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(LIFETIME_SECONDS))
                .claim("iss", issuer).claim("tid", tenant).claim(IdTokenClaimNames.AUD, List.of(CLIENT_ID)).build();
    }
}
