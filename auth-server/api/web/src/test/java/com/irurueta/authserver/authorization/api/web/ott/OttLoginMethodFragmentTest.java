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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.api.web.passkeys.PasskeyLoginMethodFragment;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link OttLoginMethodFragment}. */
class OttLoginMethodFragmentTest {

    /** Fragment under test. */
    private final OttLoginMethodFragment fragment = new OttLoginMethodFragment();

    /** The fragment is the login fragment of the login-ott template. */
    @Test
    void reference_whenAsked_pointsAtTheLoginFragmentOfTheTemplate() {
        assertEquals("login-ott :: login", fragment.reference());
    }

    /** The one-time token form comes after the passkey sign-in. */
    @Test
    void order_whenAsked_isAfterThePasskeySignIn() {
        assertEquals(OttLoginMethodFragment.ORDER, fragment.order());
        assertTrue(fragment.order() > PasskeyLoginMethodFragment.ORDER);
    }
}
