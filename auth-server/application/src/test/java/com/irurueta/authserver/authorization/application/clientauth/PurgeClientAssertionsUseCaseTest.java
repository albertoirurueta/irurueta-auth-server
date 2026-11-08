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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.clientauth.ClientAssertionReplayRegistry;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link PurgeClientAssertionsUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class PurgeClientAssertionsUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-10T00:00:00Z");

    /** Rows the registry reports removed. */
    private static final int REMOVED = 4;

    /** Port that remembers the assertions. */
    @Mock
    private ClientAssertionReplayRegistry registry;

    /** Fixed clock. */
    @Spy
    private Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    /** Subject under test. */
    @InjectMocks
    private PurgeClientAssertionsUseCase useCase;

    /**
     * Verifies that the registry is purged at the current instant and its count returned.
     */
    @Test
    void execute_whenIdentifiersExpired_returnsRemovedCount() {
        when(registry.purgeExpired(NOW)).thenReturn(REMOVED);

        assertEquals(REMOVED, useCase.execute());

        verify(registry).purgeExpired(NOW);
    }
}
