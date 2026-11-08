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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Checks the sign-in with Microsoft Entra ID for an application of a single tenant, against a fake provider: the
 * tenant of the settings is the only one that can sign in, even though the application never lists allowed tenants,
 * and its issuer is the one of that tenant. Every client id, secret and tenant is generated at run time.
 */
class SocialEntraSingleTenantIT extends AbstractSocialFlow {

    /** Client id of the application at Microsoft, generated for the run. */
    private static final String CLIENT_ID = "microsoft-" + UUID.randomUUID();

    /** The tenant of the application, generated for the run. */
    private static final String TENANT = UUID.randomUUID().toString();

    /** A tenant that is not the application's, generated for the run. */
    private static final String OTHER_TENANT = UUID.randomUUID().toString();

    /** Beginning of the issuer of a tenant. */
    private static final String ISSUER_BASE = "https://login.microsoftonline.com/";

    /** End of the issuer of a tenant. */
    private static final String ISSUER_END = "/v2.0";

    /**
     * Configures Microsoft for a single tenant.
     *
     * @param registry registry of the properties of the context.
     */
    @DynamicPropertySource
    static void providers(final DynamicPropertyRegistry registry) {
        registry.add("authserver.social.providers.microsoft.client-id", () -> CLIENT_ID);
        registry.add("authserver.social.providers.microsoft.client-secret", () -> UUID.randomUUID().toString());
        registry.add("authserver.social.providers.microsoft.tenant", () -> TENANT);
    }

    /**
     * Verifies that a token of the application's tenant signs in.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheTokenIsOfTheConfiguredTenant_signsIn() throws Exception {
        final var email = "single-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();

        signInWithOidc(session, "microsoft", ISSUER_BASE + TENANT + ISSUER_END, CLIENT_ID,
                entraClaims("entra-subject-" + UUID.randomUUID(), email, TENANT, Map.of("xms_edov", true)));

        assertEquals(email, signedInName(session).orElseThrow());
    }

    /**
     * Verifies that a token of another tenant is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void signIn_whenTheTokenIsOfAnotherTenant_isRefused() throws Exception {
        final var email = "single-other-" + UUID.randomUUID() + "@example.com";
        final var session = new MockHttpSession();

        final var result = signInWithOidc(session, "microsoft", ISSUER_BASE + OTHER_TENANT + ISSUER_END, CLIENT_ID,
                entraClaims("entra-subject-" + UUID.randomUUID(), email, OTHER_TENANT, Map.of("xms_edov", true)));

        assertRefused(result, session);
        assertTrue(accountOf(email).isEmpty());
    }
}
