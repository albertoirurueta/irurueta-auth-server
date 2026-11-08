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
package com.irurueta.authserver.bff.api.web.documents;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.bff.api.web.login.StepUpLoginParameters;
import com.irurueta.authserver.bff.domain.documents.DocumentsStepUpRequiredException;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link StepUpProblemMapper}.
 */
class StepUpProblemMapperTest {

    /** Authentication context class the resource server asks for. */
    private static final String ACR = "urn:irurueta:acr:mfa";

    /** Seconds of the maximum age the resource server asks for. */
    private static final long MAX_AGE_SECONDS = 300L;

    /** Mapper under test. */
    private final StepUpProblemMapper mapper = new StepUpProblemMapper();

    /**
     * Values within the login's limits are passed on as they are.
     */
    @Test
    void toProblemProperties_whenValuesAreAccepted_passesThemOn() {
        assertEquals(Map.of(StepUpProblemMapper.ACR_VALUES_PROPERTY, ACR + " urn:other",
                        StepUpProblemMapper.MAX_AGE_PROPERTY, MAX_AGE_SECONDS),
                mapper.toProblemProperties(stepUp(" " + ACR + "   urn:other ", Duration.ofSeconds(MAX_AGE_SECONDS))));
    }

    /**
     * A maximum age above the login's limit is capped at it, which is stricter than what was asked for.
     */
    @Test
    void toProblemProperties_whenMaxAgeExceedsTheLoginLimit_capsIt() {
        final var properties = mapper.toProblemProperties(stepUp(null, Duration.ofDays(2)));

        assertEquals(StepUpLoginParameters.MAX_AGE_LIMIT_SECONDS, properties.get(StepUpProblemMapper.MAX_AGE_PROPERTY));
    }

    /**
     * References of another format are dropped, and none are sent when none is left or the result is too long.
     */
    @Test
    void toProblemProperties_whenAcrValuesAreNotAccepted_dropsThem() {
        assertEquals(Map.of(StepUpProblemMapper.ACR_VALUES_PROPERTY, ACR),
                mapper.toProblemProperties(stepUp(ACR + " https://x.example/acr#mfa", null)));
        assertTrue(mapper.toProblemProperties(stepUp("bad\"value", null)).isEmpty());
        assertTrue(mapper.toProblemProperties(stepUp(
                "a".repeat(StepUpLoginParameters.MAX_ACR_VALUES_LENGTH + 1), null)).isEmpty());
    }

    /**
     * A step-up request that names no value gives no member.
     */
    @Test
    void toProblemProperties_whenNoValueIsNamed_returnsEmpty() {
        assertTrue(mapper.toProblemProperties(stepUp(null, null)).isEmpty());
    }

    /**
     * Builds a step-up request.
     *
     * @param acrValues references asked for, or {@code null}.
     * @param maxAge    maximum age asked for, or {@code null}.
     * @return the request.
     */
    private static DocumentsStepUpRequiredException stepUp(final String acrValues, final Duration maxAge) {
        return new DocumentsStepUpRequiredException("step-up", acrValues, maxAge, null);
    }
}
