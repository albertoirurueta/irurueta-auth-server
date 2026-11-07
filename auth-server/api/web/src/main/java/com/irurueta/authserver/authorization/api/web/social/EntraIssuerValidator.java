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

import java.util.List;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

// tag::social-entra-validator[]
/**
 * Validates the issuer of an ID token of Microsoft Entra ID in a multi-tenant application.
 *
 * <p>Such a token is issued by the tenant its user belongs to ({@code https://login.microsoftonline.com/{tid}/v2.0})
 * while the discovery document of the {@code common} endpoint advertises a {@code {tenantid}} placeholder as the
 * issuer, so the framework's check against one fixed issuer would reject every token. This validator takes the tenant
 * from the token's own {@code tid} claim, requires the {@code iss} to be exactly that tenant's issuer, and, when a list
 * is given, requires the tenant to be one of the permitted ones. The signature has already been verified against
 * Entra's published keys by then, so the {@code tid} is the one Entra put in the token.
 */
public class EntraIssuerValidator implements OAuth2TokenValidator<Jwt> {

    /** Claim that holds the id of the tenant the user belongs to. */
    static final String TENANT_CLAIM = "tid";

    /** Error code of a refused token. */
    static final String INVALID_TOKEN = "invalid_id_token";

    /** Tenants accepted; empty accepts any tenant. */
    private final List<String> permittedTenants;

    /**
     * Creates the validator.
     *
     * @param permittedTenants ids of the tenants accepted, compared ignoring case; empty accepts any tenant.
     */
    public EntraIssuerValidator(final List<String> permittedTenants) {
        this.permittedTenants = List.copyOf(permittedTenants);
    }

    /**
     * Validates the issuer of a token.
     *
     * @param token the ID token, already decoded and signature-verified.
     * @return a success, or a failure when the token has no tenant, its issuer is not the issuer of its tenant, or its
     *         tenant is not permitted.
     */
    @Override
    public OAuth2TokenValidatorResult validate(final Jwt token) {
        final var tenant = token.getClaimAsString(TENANT_CLAIM);
        final var issuer = token.getClaim("iss");
        if (!StringUtils.hasText(tenant)) {
            return failure("The ID token has no tenant");
        }
        if (issuer == null
                || !(ClientRegistrationMapper.ENTRA_BASE_URL + tenant + "/v2.0").equals(issuer.toString())) {
            return failure("The issuer of the ID token is not the issuer of its tenant");
        }
        if (!permittedTenants.isEmpty()
                && permittedTenants.stream().noneMatch(permitted -> permitted.equalsIgnoreCase(tenant))) {
            return failure("The tenant of the ID token is not permitted");
        }
        return OAuth2TokenValidatorResult.success();
    }

    /**
     * Builds a failed result.
     *
     * @param description the reason.
     * @return the result.
     */
    private static OAuth2TokenValidatorResult failure(final String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(INVALID_TOKEN, description, null));
    }
}
// end::social-entra-validator[]
