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

package com.irurueta.authserver.authorization.api.web.password;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PasswordLoginFragment}.
 */
class PasswordLoginFragmentTest {

    /** Fragment under test. */
    private final PasswordLoginFragment fragment = new PasswordLoginFragment();

    /**
     * Verifies that the fragment is the form of the password template.
     */
    @Test
    void reference_whenAsked_pointsAtTheFormFragmentOfThePasswordTemplate() {
        assertEquals("password :: form", fragment.reference());
    }

    /**
     * Verifies that the password form is rendered first.
     */
    @Test
    void order_whenAsked_isTheFirstPosition() {
        assertEquals(PasswordLoginFragment.ORDER, fragment.order());
    }
}
