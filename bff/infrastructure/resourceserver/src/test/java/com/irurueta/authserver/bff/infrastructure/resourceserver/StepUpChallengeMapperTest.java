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
package com.irurueta.authserver.bff.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;

/**
 * Unit tests of {@link StepUpChallengeMapper}.
 */
class StepUpChallengeMapperTest {

    /** Authentication context class asked for. */
    private static final String ACR = "urn:irurueta:acr:mfa";

    /** Seconds of the maximum age asked for. */
    private static final long MAX_AGE_SECONDS = 300L;

    /** A complete step-up challenge as the resource server sends it. */
    private static final String STEP_UP = "Bearer error=\"insufficient_user_authentication\", "
            + "error_description=\"A different authentication level is required\", acr_values=\"" + ACR
            + "\", max_age=\"" + MAX_AGE_SECONDS + "\"";

    /** Mapper under test. */
    private final StepUpChallengeMapper mapper = new StepUpChallengeMapper();

    /**
     * A step-up challenge becomes a step-up request with its values and the given cause.
     */
    @Test
    void toException_whenChallengeAsksForStepUp_returnsItsValues() {
        final var cause = new IllegalStateException("401");

        final var error = mapper.toException(headersWith(STEP_UP), cause).orElseThrow();

        assertEquals(Optional.of(ACR), error.getAcrValues());
        assertEquals(Optional.of(Duration.ofSeconds(MAX_AGE_SECONDS)), error.getMaxAge());
        assertSame(cause, error.getCause());
    }

    /**
     * The scheme and parameter names are case-insensitive, values may be bare tokens and a quoted value may carry
     * escaped characters.
     */
    @Test
    void toException_whenChallengeUsesOtherCaseTokensAndEscapes_readsIt() {
        final var error = mapper.toException(headersWith(
                "BEARER ERROR=insufficient_user_authentication, ACR_VALUES=\"a\\\"b c\", MAX_AGE=60"), null)
                .orElseThrow();

        assertEquals(Optional.of("a\"b c"), error.getAcrValues());
        assertEquals(Optional.of(Duration.ofMinutes(1)), error.getMaxAge());
    }

    /**
     * A step-up challenge without values is still a step-up request.
     */
    @Test
    void toException_whenChallengeNamesNoValues_returnsThemEmpty() {
        final var error = mapper.toException(headersWith("Bearer error=\"insufficient_user_authentication\""),
                null).orElseThrow();

        assertTrue(error.getAcrValues().isEmpty());
        assertTrue(error.getMaxAge().isEmpty());
    }

    /**
     * A maximum age that is not a non-negative number is ignored.
     *
     * @param maxAge the value of the parameter.
     */
    @ParameterizedTest
    @ValueSource(strings = {"\"\"", "\"-1\"", "\"abc\"", "\"99999999999999999999\""})
    void toException_whenMaxAgeIsInvalid_ignoresIt(final String maxAge) {
        final var error = mapper.toException(headersWith(
                "Bearer error=\"insufficient_user_authentication\", max_age=" + maxAge), null).orElseThrow();

        assertTrue(error.getMaxAge().isEmpty());
    }

    /**
     * Challenges that are not bearer step-up challenges are not step-up requests.
     *
     * @param challenge the value of the header.
     */
    @ParameterizedTest
    @ValueSource(strings = {
        "Bearer error=\"invalid_token\"",
        "Bearer",
        "Bearerx error=\"insufficient_user_authentication\"",
        "Basic realm=\"x\", error=\"insufficient_user_authentication\"",
        "Bearer realm=\"x\""})
    void toException_whenChallengeIsNotStepUp_returnsEmpty(final String challenge) {
        assertTrue(mapper.toException(headersWith(challenge), null).isEmpty());
    }

    /**
     * A step-up challenge is found among several challenges.
     */
    @Test
    void toException_whenSeveralChallengesAreSent_findsTheStepUpOne() {
        final var headers = headersWith("Basic realm=\"x\"");
        headers.add(HttpHeaders.WWW_AUTHENTICATE, STEP_UP);

        assertTrue(mapper.toException(headers, null).isPresent());
    }

    /**
     * An answer without headers, or without a challenge, is not a step-up request.
     */
    @Test
    void toException_whenThereIsNoChallenge_returnsEmpty() {
        assertTrue(mapper.toException(null, null).isEmpty());
        assertTrue(mapper.toException(new HttpHeaders(), null).isEmpty());
    }

    /**
     * Builds headers carrying one challenge.
     *
     * @param challenge the value of the {@code WWW-Authenticate} header.
     * @return the headers.
     */
    private static HttpHeaders headersWith(final String challenge) {
        final var headers = new HttpHeaders();
        headers.add(HttpHeaders.WWW_AUTHENTICATE, challenge);
        return headers;
    }
}
