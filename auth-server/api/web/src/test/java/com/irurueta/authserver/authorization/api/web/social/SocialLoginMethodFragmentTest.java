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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.api.web.ott.OttLoginMethodFragment;
import com.irurueta.authserver.authorization.api.web.passkeys.PasskeyLoginMethodFragment;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SocialLoginMethodFragment}.
 */
class SocialLoginMethodFragmentTest {

    /** Fragment under test. */
    private final SocialLoginMethodFragment fragment =
            new SocialLoginMethodFragment(List.of("google", "github"));

    /**
     * Verifies that the fragment is the login fragment of the social template.
     */
    @Test
    void reference_whenAsked_pointsAtTheLoginFragmentOfTheSocialTemplate() {
        assertEquals("login-social :: login", fragment.reference());
    }

    /**
     * Verifies that the providers are offered after the passkeys and before the one-time tokens.
     */
    @Test
    void order_whenAsked_isAfterThePasskeysAndBeforeTheOneTimeTokens() {
        assertEquals(SocialLoginMethodFragment.ORDER, fragment.order());
        assertTrue(fragment.order() > PasskeyLoginMethodFragment.ORDER);
        assertTrue(fragment.order() < OttLoginMethodFragment.ORDER);
    }

    /**
     * Verifies the providers offered.
     */
    @Test
    void providers_whenAsked_listsTheConfiguredOnes() {
        assertEquals(List.of("google", "github"), fragment.providers());
        assertFalse(fragment.providers().contains("apple"));
    }
}
