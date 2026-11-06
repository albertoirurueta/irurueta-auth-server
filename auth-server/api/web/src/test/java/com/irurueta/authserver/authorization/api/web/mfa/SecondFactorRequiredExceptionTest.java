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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SecondFactorRequiredException}.
 */
class SecondFactorRequiredExceptionTest {

    /**
     * Verifies the error code carried by the exception.
     */
    @Test
    void constructor_whenCreated_carriesTheSecondFactorErrorCode() {
        final var exception = new SecondFactorRequiredException();

        assertEquals(SecondFactorRequiredException.ERROR_CODE, exception.getError().getErrorCode());
        assertFalse(exception.isStepUp());
    }

    /**
     * Verifies that a step-up exception says so and carries the same error code.
     */
    @Test
    void forStepUp_whenCreated_isAStepUp() {
        final var exception = SecondFactorRequiredException.forStepUp();

        assertTrue(exception.isStepUp());
        assertEquals(SecondFactorRequiredException.ERROR_CODE, exception.getError().getErrorCode());
    }
}
