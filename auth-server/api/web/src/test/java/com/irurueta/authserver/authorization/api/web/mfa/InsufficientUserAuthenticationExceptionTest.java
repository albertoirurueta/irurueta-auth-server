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

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link InsufficientUserAuthenticationException}.
 */
class InsufficientUserAuthenticationExceptionTest {

    /** Maximum age used by the test, in minutes. */
    private static final int MAX_AGE_MINUTES = 5;

    /**
     * Verifies that the exception carries what the client must ask for, and says it in its message.
     */
    @Test
    void constructor_whenCreated_carriesTheAcrValuesAndTheMaxAge() {
        final var maxAge = Duration.ofMinutes(MAX_AGE_MINUTES);

        final var exception = new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                maxAge);

        assertEquals(AuthenticationContextClass.MULTI_FACTOR, exception.getAcrValues());
        assertEquals(maxAge, exception.getMaxAge());
        assertEquals("A multi-factor sign-in within the last 300 seconds is required", exception.getMessage());
    }
}
