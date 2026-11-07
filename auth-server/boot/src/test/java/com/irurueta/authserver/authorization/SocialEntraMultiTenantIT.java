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
package com.irurueta.authserver.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Checks the sign-in with Microsoft Entra ID as a multi-tenant application restricted to a list of tenants, against a
 * fake provider: the issuer of an Entra ID token is the issuer of the tenant the token comes from, so it is checked
 * against the token's own tenant, and the tenant has to be one of the allowed ones. A token of a tenant that is not
 * allowed, a token whose issuer is another tenant's and an address Entra does not vouch for are all refused, and an
 * address Entra marks as verified by either of its claims is accepted. Every client id, secret and tenant is
 * generated at run time.
 */
class SocialEntraMultiTenantIT extends AbstractSocialFlow {

    /** Client id of the application at Microsoft, generated for the run. */
    private static final String CLIENT_ID = "microsoft-" + UUID.randomUUID();

    /** The tenant that is allowed to sign in, generated for the run. */
    private static final String ALLOWED_TENANT = UUID.randomUUID().toString();

    /** A tenant that is not allowed, generated for the run. */
    private static final String OTHER_TENANT = UUID.randomUUID().toString();

    /** Beginning of the issuer of a tenant. */
    private static final String ISSUER_BASE = "https://login.microsoftonline.com/";

    /** End of the issuer of a tenant. */
    private static final String ISSUER_END = "/v2.0";

    /**
     * Configures Microsoft as a multi-tenant application restricted to one tenant.
     *
     * @param registry registry of the properties of the context.
     */
    @DynamicPropertySource
    static void providers(final DynamicPropertyRegistry registry) {
        registry.add("authserver.social.providers.microsoft.client-id", () -> CLIENT_ID);
        registry.add("authserver.social.providers.microsoft.client-secret", () -> UUID.randomUUID().toString());
        registry.add("authserver.social.providers.microsoft.tenant", () -> "organizations");
        registry.add("authserver.social.providers.microsoft.allowed-tenants", () -> ALLOWED_TENANT);
    }

    /**
     * Verifies that a token of the allowed tenant, issued by that tenant, provisions an account when Entra marks the
     * address as verified with its own claim.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheTokenIsOfAnAllowedTenant_provisionsAndLinksAnAccount() throws Exception {
        final var email = "entra-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();

        signInWithOidc(session, "microsoft", issuerOf(ALLOWED_TENANT), CLIENT_ID,
                entraClaims("entra-subject-" + UUID.randomUUID(), email, ALLOWED_TENANT, Map.of("xms_edov", true)));

        assertEquals(email, signedInName(session).orElseThrow());
        assertEquals(IdentityProvider.MICROSOFT, identitiesOf(accountOf(email).orElseThrow()).getFirst().provider());
    }

    /**
     * Verifies that the standard verified-address claim is accepted as well.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheStandardVerifiedClaimIsPresent_provisionsAnAccount() throws Exception {
        final var email = "entra-standard-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();

        signInWithOidc(session, "microsoft", issuerOf(ALLOWED_TENANT), CLIENT_ID,
                entraClaims("entra-subject-" + UUID.randomUUID(), email, ALLOWED_TENANT,
                        Map.of("email_verified", true)));

        assertEquals(email, signedInName(session).orElseThrow());
    }

    /**
     * Verifies that a token of a tenant that is not on the list is refused, though its issuer is that tenant's own.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheTenantIsNotAllowed_isRefused() throws Exception {
        final var email = "other-tenant-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();

        final var result = signInWithOidc(session, "microsoft", issuerOf(OTHER_TENANT), CLIENT_ID,
                entraClaims("entra-subject-" + UUID.randomUUID(), email, OTHER_TENANT, Map.of("xms_edov", true)));

        assertRefused(result, session);
        assertTrue(accountOf(email).isEmpty());
    }

    /**
     * Verifies that a token whose issuer is the issuer of another tenant than the one it claims to come from is
     * refused: an allowed tenant id cannot be borrowed.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheIssuerIsNotTheIssuerOfTheTokensTenant_isRefused() throws Exception {
        final var email = "mixed-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();

        final var result = signInWithOidc(session, "microsoft", issuerOf(OTHER_TENANT), CLIENT_ID,
                entraClaims("entra-subject-" + UUID.randomUUID(), email, ALLOWED_TENANT, Map.of("xms_edov", true)));

        assertRefused(result, session);
        assertTrue(accountOf(email).isEmpty());
    }

    /**
     * Verifies that an address Entra does not vouch for, which any tenant admin can set to anything, never links to
     * the account that owns it nor provisions an account.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenEntraDoesNotVouchForTheEmail_isRefusedAndLinksNothing() throws Exception {
        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();

        final var result = signInWithOidc(session, "microsoft", issuerOf(ALLOWED_TENANT), CLIENT_ID,
                entraClaims("entra-subject-" + UUID.randomUUID(), user.email(), ALLOWED_TENANT, Map.of()));

        assertRefused(result, session);
        assertFalse(identitiesOf(accountOf(user.email()).orElseThrow()).stream()
                .anyMatch(identity -> identity.provider() == IdentityProvider.MICROSOFT));
    }

    /**
     * Gives the issuer of a tenant.
     *
     * @param tenant the tenant id.
     * @return its issuer.
     */
    private static String issuerOf(final String tenant) {
        return ISSUER_BASE + tenant + ISSUER_END;
    }
}
