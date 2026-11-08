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
package com.irurueta.authserver.bff.domain.documents;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DocumentsStepUpRequiredException}.
 */
class DocumentsStepUpRequiredExceptionTest {

    /** Message used by the tests. */
    private static final String MESSAGE = "step-up";

    /** Authentication context class asked for. */
    private static final String ACR_VALUES = "urn:irurueta:acr:mfa";

    /** Seconds of the maximum age asked for. */
    private static final long MAX_AGE_SECONDS = 300L;

    /** Every value given is kept. */
    @Test
    void constructor_whenValuesAreGiven_keepsThem() {
        final var cause = new IllegalStateException("cause");
        final var maxAge = Duration.ofSeconds(MAX_AGE_SECONDS);

        final var error = new DocumentsStepUpRequiredException(MESSAGE, ACR_VALUES, maxAge, cause);

        assertEquals(MESSAGE, error.getMessage());
        assertEquals(Optional.of(ACR_VALUES), error.getAcrValues());
        assertEquals(Optional.of(maxAge), error.getMaxAge());
        assertSame(cause, error.getCause());
    }

    /** A challenge that names neither value, and has no cause, is allowed. */
    @Test
    void constructor_whenValuesAreNull_reportsThemEmpty() {
        final var error = new DocumentsStepUpRequiredException(MESSAGE, null, null, null);

        assertTrue(error.getAcrValues().isEmpty());
        assertTrue(error.getMaxAge().isEmpty());
        assertNull(error.getCause());
    }
}
