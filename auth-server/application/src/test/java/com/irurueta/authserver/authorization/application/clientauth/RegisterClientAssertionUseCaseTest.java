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

package com.irurueta.authserver.authorization.application.clientauth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.clientauth.ClientAssertionReplayRegistry;
import com.irurueta.authserver.authorization.domain.clientauth.ClientAssertionUse;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RegisterClientAssertionUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RegisterClientAssertionUseCaseTest {

    /** Client identifier. */
    private static final String CLIENT_ID = "client";

    /** Assertion identifier. */
    private static final String JTI = "jti-1";

    /** Expiry. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-10T00:05:00Z");

    /** Port that remembers the assertions. */
    @Mock
    private ClientAssertionReplayRegistry registry;

    /** Subject under test. */
    @InjectMocks
    private RegisterClientAssertionUseCase useCase;

    /**
     * Verifies that a first use is reported as such.
     */
    @Test
    void execute_whenFirstUse_returnsTrue() {
        when(registry.register(CLIENT_ID, JTI, EXPIRES_AT)).thenReturn(true);

        assertTrue(useCase.execute(new ClientAssertionUse(CLIENT_ID, JTI, EXPIRES_AT)));

        verify(registry).register(CLIENT_ID, JTI, EXPIRES_AT);
    }

    /**
     * Verifies that a replay is reported as such.
     */
    @Test
    void execute_whenReplayed_returnsFalse() {
        when(registry.register(CLIENT_ID, JTI, EXPIRES_AT)).thenReturn(false);

        assertFalse(useCase.execute(new ClientAssertionUse(CLIENT_ID, JTI, EXPIRES_AT)));
    }
}
