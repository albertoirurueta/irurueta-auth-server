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

package com.irurueta.authserver.resourceserver.api.web.security;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link StepUpProperties}. */
class StepUpPropertiesTest {

    /** A blank acr is rejected. */
    @Test
    void constructor_whenAcrIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new StepUpProperties(true, " ", Duration.ofMinutes(1)));
    }

    /** A missing max age is rejected. */
    @Test
    void constructor_whenMaxAgeIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new StepUpProperties(true, "acr", null));
    }

    /** A zero max age is rejected. */
    @Test
    void constructor_whenMaxAgeIsZero_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new StepUpProperties(true, "acr", Duration.ZERO));
    }

    /** A negative max age is rejected. */
    @Test
    void constructor_whenMaxAgeIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new StepUpProperties(true, "acr", Duration.ofSeconds(-1)));
    }
}
