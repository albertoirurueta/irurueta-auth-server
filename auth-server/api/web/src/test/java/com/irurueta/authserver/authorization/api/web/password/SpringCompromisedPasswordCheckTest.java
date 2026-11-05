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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;

/**
 * Unit tests of {@link SpringCompromisedPasswordCheck}.
 */
@ExtendWith(MockitoExtension.class)
class SpringCompromisedPasswordCheckTest {

    /** Clear-text value used by the tests; not a real credential. */
    private static final String RAW = "raw-value";

    /** Checker the adapter delegates to. */
    @Mock
    private CompromisedPasswordChecker checker;

    /** Adapter under test. */
    @InjectMocks
    private SpringCompromisedPasswordCheck check;

    /**
     * Verifies that a compromised decision is reported as compromised.
     */
    @Test
    void isCompromised_whenCheckerSaysCompromised_returnsTrue() {
        when(checker.check(RAW)).thenReturn(new CompromisedPasswordDecision(true));

        assertTrue(check.isCompromised(RAW));
    }

    /**
     * Verifies that a clean decision is reported as not compromised.
     */
    @Test
    void isCompromised_whenCheckerSaysClean_returnsFalse() {
        when(checker.check(RAW)).thenReturn(new CompromisedPasswordDecision(false));

        assertFalse(check.isCompromised(RAW));
    }
}
