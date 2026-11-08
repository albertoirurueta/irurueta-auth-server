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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.clientauth.ClientAssertionProperties;
import com.irurueta.authserver.authorization.application.clientauth.RegisterClientAssertionUseCase;
import com.irurueta.authserver.authorization.domain.clientauth.ClientAssertionUse;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;

/** Unit tests of {@link ReplayRejectingJwtValidator}. */
@ExtendWith(MockitoExtension.class)
class ReplayRejectingJwtValidatorTest {

    /** Client of the assertions. */
    private static final String CLIENT_ID = "client-1";

    /** Identifier of the assertions. */
    private static final String JTI = "jti-1";

    /** Longest lifetime accepted. */
    private static final Duration MAX_LIFETIME = Duration.ofMinutes(5);

    /** A lifetime within the maximum. */
    private static final Duration SHORT_LIFETIME = Duration.ofMinutes(1);

    /** The instant the assertions were issued. */
    private static final Instant ISSUED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /** Records the use of an assertion. */
    @Mock
    private RegisterClientAssertionUseCase registerClientAssertion;

    /** Validator under test. */
    private ReplayRejectingJwtValidator validator;

    /** Creates the validator with a five minute limit. */
    @BeforeEach
    void setUp() {
        validator = new ReplayRejectingJwtValidator(registerClientAssertion,
                new ClientAssertionProperties(MAX_LIFETIME, null));
    }

    /** A new assertion is accepted and its use recorded with the client, identifier and expiry. */
    @Test
    void validate_whenAssertionIsNew_succeedsAndRegistersIt() {
        when(registerClientAssertion.execute(any())).thenReturn(true);

        final var result = validator.validate(jwt(CLIENT_ID, JTI, ISSUED_AT, ISSUED_AT.plus(SHORT_LIFETIME)));

        assertFalse(result.hasErrors());
        final var captor = ArgumentCaptor.<ClientAssertionUse>captor();
        verify(registerClientAssertion).execute(captor.capture());
        assertEquals(new ClientAssertionUse(CLIENT_ID, JTI, ISSUED_AT.plus(SHORT_LIFETIME)), captor.getValue());
    }

    /** An assertion of exactly the maximum lifetime is accepted. */
    @Test
    void validate_whenLifetimeEqualsTheMaximum_succeeds() {
        when(registerClientAssertion.execute(any())).thenReturn(true);

        assertFalse(validator.validate(jwt(CLIENT_ID, JTI, ISSUED_AT, ISSUED_AT.plus(MAX_LIFETIME))).hasErrors());
    }

    /** A replayed assertion is refused with invalid_client. */
    @Test
    void validate_whenJtiWasAlreadyUsed_failsWithInvalidClient() {
        when(registerClientAssertion.execute(any())).thenReturn(false);

        final var result = validator.validate(jwt(CLIENT_ID, JTI, ISSUED_AT, ISSUED_AT.plus(SHORT_LIFETIME)));

        assertTrue(result.hasErrors());
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, result.getErrors().iterator().next().getErrorCode());
    }

    /** An assertion that lives longer than the maximum is refused and does not consume its identifier. */
    @Test
    void validate_whenLifetimeExceedsTheMaximum_failsWithoutRegistering() {
        final var result = validator.validate(
                jwt(CLIENT_ID, JTI, ISSUED_AT, ISSUED_AT.plus(MAX_LIFETIME).plusSeconds(1)));

        assertTrue(result.hasErrors());
        verify(registerClientAssertion, never()).execute(any());
    }

    /** An assertion without jti is refused. */
    @Test
    void validate_whenJtiIsMissing_fails() {
        assertTrue(validator.validate(jwt(CLIENT_ID, null, ISSUED_AT, ISSUED_AT.plus(SHORT_LIFETIME))).hasErrors());
        verify(registerClientAssertion, never()).execute(any());
    }

    /** An assertion without iat is refused. */
    @Test
    void validate_whenIssuedAtIsMissing_fails() {
        assertTrue(validator.validate(jwt(CLIENT_ID, JTI, null, ISSUED_AT.plus(SHORT_LIFETIME))).hasErrors());
        verify(registerClientAssertion, never()).execute(any());
    }

    /** An assertion without exp is refused. */
    @Test
    void validate_whenExpiresAtIsMissing_fails() {
        assertTrue(validator.validate(jwt(CLIENT_ID, JTI, ISSUED_AT, null)).hasErrors());
        verify(registerClientAssertion, never()).execute(any());
    }

    /** An assertion without sub is refused. */
    @Test
    void validate_whenSubjectIsMissing_fails() {
        assertTrue(validator.validate(jwt(null, JTI, ISSUED_AT, ISSUED_AT.plus(SHORT_LIFETIME))).hasErrors());
        verify(registerClientAssertion, never()).execute(any());
    }

    /**
     * Builds an assertion.
     *
     * @param subject   the {@code sub}, or {@code null}.
     * @param jti       the {@code jti}, or {@code null}.
     * @param issuedAt  the {@code iat}, or {@code null}.
     * @param expiresAt the {@code exp}, or {@code null}.
     * @return the assertion.
     */
    private static Jwt jwt(final String subject, final String jti, final Instant issuedAt, final Instant expiresAt) {
        final var builder = Jwt.withTokenValue("token").header("alg", "ES256");
        if (subject != null) {
            builder.subject(subject);
        }
        if (jti != null) {
            builder.jti(jti);
        }
        if (issuedAt != null) {
            builder.issuedAt(issuedAt);
        }
        if (expiresAt != null) {
            builder.expiresAt(expiresAt);
        }
        return builder.build();
    }
}
