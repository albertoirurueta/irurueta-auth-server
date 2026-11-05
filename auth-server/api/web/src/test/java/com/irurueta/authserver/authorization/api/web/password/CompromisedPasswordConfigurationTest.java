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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link CompromisedPasswordConfiguration}.
 */
class CompromisedPasswordConfigurationTest {

    /** Configuration under test. */
    private final CompromisedPasswordConfiguration configuration = new CompromisedPasswordConfiguration();

    /**
     * Verifies that the enabled check is the Spring Security adapter.
     */
    @Test
    void haveIBeenPwnedCompromisedPasswordCheck_whenCalled_returnsSpringAdapter() {
        assertInstanceOf(SpringCompromisedPasswordCheck.class,
                configuration.haveIBeenPwnedCompromisedPasswordCheck());
    }

    /**
     * Verifies that the no-op check never reports a password as compromised.
     */
    @Test
    void noOpCompromisedPasswordCheck_whenCalled_neverReportsCompromised() {
        assertFalse(configuration.noOpCompromisedPasswordCheck().isCompromised("any-value"));
    }
}
