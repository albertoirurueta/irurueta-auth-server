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
package com.irurueta.authserver.authorization.application.mfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link HasConfirmedSecondFactorUseCase}. The subject takes a list of queries, which
 * {@code @InjectMocks} cannot build from {@code @Mock} fields, so each test builds it with its own mocks.
 */
class HasConfirmedSecondFactorUseCaseTest {

    /** Identifier of the user. */
    private final UUID userId = UUID.randomUUID();

    /**
     * Verifies that one confirmed second factor is enough.
     */
    @Test
    void execute_whenOneQueryConfirms_returnsTrue() {
        final var none = mock(SecondFactorEnrolmentQuery.class);
        final var confirmed = mock(SecondFactorEnrolmentQuery.class);
        when(none.hasConfirmed(userId)).thenReturn(false);
        when(confirmed.hasConfirmed(userId)).thenReturn(true);

        assertTrue(new HasConfirmedSecondFactorUseCase(List.of(none, confirmed)).execute(userId));
    }

    /**
     * Verifies that no confirmed second factor answers false.
     */
    @Test
    void execute_whenNoQueryConfirms_returnsFalse() {
        final var none = mock(SecondFactorEnrolmentQuery.class);
        when(none.hasConfirmed(userId)).thenReturn(false);

        assertFalse(new HasConfirmedSecondFactorUseCase(List.of(none)).execute(userId));
    }

    /**
     * Verifies that, when no second factor is registered at all, nobody has one.
     */
    @Test
    void execute_whenNoQueryIsRegistered_returnsFalse() {
        assertFalse(new HasConfirmedSecondFactorUseCase(List.<SecondFactorEnrolmentQuery>of()).execute(userId));
    }
}
