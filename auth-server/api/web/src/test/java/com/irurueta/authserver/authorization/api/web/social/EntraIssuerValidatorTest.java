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

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Unit tests of {@link EntraIssuerValidator}.
 */
class EntraIssuerValidatorTest {

    /** Tenant of the tokens. */
    private static final String TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";

    /** Issuer of the tenant. */
    private static final String ISSUER = "https://login.microsoftonline.com/" + TENANT + "/v2.0";

    /** Lifetime of the test tokens, in seconds. */
    private static final long LIFETIME_SECONDS = 60L;

    /**
     * Verifies that a token issued by its own tenant is accepted when any tenant is.
     */
    @Test
    void validate_whenIssuerIsTheIssuerOfTheTokenTenant_succeeds() {
        assertFalse(new EntraIssuerValidator(List.of()).validate(token(ISSUER, TENANT)).hasErrors());
    }

    /**
     * Verifies that the issuer must be the one of the tenant the token names: a token that claims another tenant's
     * issuer is refused.
     */
    @Test
    void validate_whenIssuerBelongsToAnotherTenant_fails() {
        final var issuer = "https://login.microsoftonline.com/other/v2.0";

        assertTrue(new EntraIssuerValidator(List.of()).validate(token(issuer, TENANT)).hasErrors());
    }

    /**
     * Verifies that a token with no tenant or no issuer is refused.
     */
    @Test
    void validate_whenTenantOrIssuerIsMissing_fails() {
        final var validator = new EntraIssuerValidator(List.of());

        assertTrue(validator.validate(token(ISSUER, null)).hasErrors());
        assertTrue(validator.validate(token(null, TENANT)).hasErrors());
    }

    /**
     * Verifies that a tenant outside the permitted list is refused, whatever the case it is written in, and one in it
     * is accepted.
     */
    @Test
    void validate_whenTenantIsNotPermitted_fails() {
        final var permitted = new EntraIssuerValidator(List.of(TENANT.toUpperCase(Locale.ROOT)));
        final var others = new EntraIssuerValidator(List.of("other-tenant"));

        assertFalse(permitted.validate(token(ISSUER, TENANT)).hasErrors());
        assertTrue(others.validate(token(ISSUER, TENANT)).hasErrors());
    }

    /**
     * Builds a token.
     *
     * @param issuer issuer claim, or {@code null}.
     * @param tenant tenant claim, or {@code null}.
     * @return the token.
     */
    private static Jwt token(final String issuer, final String tenant) {
        final var builder = Jwt.withTokenValue("token").header("alg", "RS256").subject("sub")
                .issuedAt(Instant.EPOCH).expiresAt(Instant.EPOCH.plusSeconds(LIFETIME_SECONDS));
        if (issuer != null) {
            builder.claim("iss", issuer);
        }
        if (tenant != null) {
            builder.claim("tid", tenant);
        }
        return builder.build();
    }
}
