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

package com.irurueta.authserver.authorization.domain.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link InvalidPasswordException}.
 */
class InvalidPasswordExceptionTest {

    /**
     * Verifies that the violations are kept and described.
     */
    @Test
    void constructor_whenViolationsAreGiven_keepsThem() {
        final var violations = new ArrayList<>(List.of(PasswordViolation.TOO_SHORT));

        final var error = new InvalidPasswordException(violations);
        violations.add(PasswordViolation.TOO_LONG);

        assertEquals(List.of(PasswordViolation.TOO_SHORT), error.getViolations());
        assertTrue(error.getMessage().contains("TOO_SHORT"));
    }
}
