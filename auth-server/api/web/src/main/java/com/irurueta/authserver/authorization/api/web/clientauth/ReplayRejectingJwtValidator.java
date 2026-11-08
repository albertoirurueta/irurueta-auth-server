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
package com.irurueta.authserver.authorization.api.web.clientauth;

import com.irurueta.authserver.authorization.application.clientauth.ClientAssertionProperties;
import com.irurueta.authserver.authorization.application.clientauth.RegisterClientAssertionUseCase;
import com.irurueta.authserver.authorization.domain.clientauth.ClientAssertionUse;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

// tag::clientauth-replay-validator[]
/**
 * Validates what the framework's default assertion validators leave out: the assertion must carry a {@code jti}, an
 * {@code iat} and an {@code exp} no more than the configured maximum lifetime after it, and its {@code jti} must not
 * have been used before by the same client (RFC 7523, section 3). The use is recorded last, only for an assertion
 * that passed the other checks, so a refused assertion never consumes its identifier. The record is made through
 * {@link RegisterClientAssertionUseCase}, so the replay protection is shared by every instance of the server.
 */
@RequiredArgsConstructor
public class ReplayRejectingJwtValidator implements OAuth2TokenValidator<Jwt> {

    /** Description of the failures. */
    private static final String DESCRIPTION_PREFIX = "The client assertion ";

    /** Remembers the assertions that were accepted. */
    private final RegisterClientAssertionUseCase registerClientAssertion;

    /** Settings of the client assertions, for the longest lifetime. */
    private final ClientAssertionProperties properties;

    /**
     * Checks the assertion and records its use.
     *
     * @param jwt the assertion, already verified for signature, issuer, subject, audience and expiry.
     * @return success, or a failure when the {@code jti}, {@code iat} or {@code exp} is missing, the lifetime is
     *         longer than allowed or the {@code jti} was already used.
     */
    @Override
    public OAuth2TokenValidatorResult validate(final Jwt jwt) {
        if (!StringUtils.hasText(jwt.getId())) {
            return failure("must have a jti");
        }
        final var issuedAt = jwt.getIssuedAt();
        final var expiresAt = jwt.getExpiresAt();
        if (issuedAt == null) {
            return failure("must have an iat");
        }
        if (expiresAt == null) {
            return failure("must have an exp");
        }
        final var maxLifetime = properties.maxLifetime();
        if (Duration.between(issuedAt, expiresAt).compareTo(maxLifetime) > 0) {
            return failure("lives longer than " + maxLifetime);
        }
        final var clientId = jwt.getSubject();
        if (!StringUtils.hasText(clientId)) {
            return failure("must have a sub");
        }
        if (!registerClientAssertion.execute(new ClientAssertionUse(clientId, jwt.getId(), expiresAt))) {
            return failure("was already used");
        }
        return OAuth2TokenValidatorResult.success();
    }

    /**
     * Builds a failure.
     *
     * @param reason what is wrong with the assertion.
     * @return the failed result.
     */
    private static OAuth2TokenValidatorResult failure(final String reason) {
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, DESCRIPTION_PREFIX + reason, null));
    }
}
// end::clientauth-replay-validator[]
