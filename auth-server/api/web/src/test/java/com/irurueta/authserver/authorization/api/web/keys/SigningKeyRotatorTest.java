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

package com.irurueta.authserver.authorization.api.web.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.keys.RotateSigningKeysUseCase;
import com.irurueta.authserver.authorization.application.keys.SigningKeysRotatedEvent;
import java.time.Clock;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Unit tests of {@link SigningKeyRotator}.
 */
@ExtendWith(MockitoExtension.class)
class SigningKeyRotatorTest {

    /** Instant returned by the clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Rotates the keys. */
    @Mock
    private RotateSigningKeysUseCase rotateSigningKeysUseCase;

    /** Publishes events. */
    @Mock
    private ApplicationEventPublisher eventPublisher;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Subject under test. */
    @InjectMocks
    private SigningKeyRotator rotator;

    /**
     * The event is published after the rotation, stamped with the clock.
     */
    @Test
    void rotate_whenCalled_rotatesThenPublishesEvent() {
        when(clock.instant()).thenReturn(NOW);
        final var captor = ArgumentCaptor.<Object>captor();

        rotator.rotate();

        final var order = inOrder(rotateSigningKeysUseCase, eventPublisher);
        order.verify(rotateSigningKeysUseCase).execute();
        order.verify(eventPublisher).publishEvent(captor.capture());
        assertEquals(new SigningKeysRotatedEvent(NOW), captor.getValue());
    }

    /**
     * A forced rotation runs the forced path of the use case, never the due-only one, then publishes the event.
     */
    @Test
    void rotateNow_whenCalled_forcesTheRotationThenPublishesEvent() {
        when(clock.instant()).thenReturn(NOW);
        final var captor = ArgumentCaptor.<Object>captor();

        rotator.rotateNow();

        final var order = inOrder(rotateSigningKeysUseCase, eventPublisher);
        order.verify(rotateSigningKeysUseCase).executeForced();
        order.verify(eventPublisher).publishEvent(captor.capture());
        assertEquals(new SigningKeysRotatedEvent(NOW), captor.getValue());
        verify(rotateSigningKeysUseCase, never()).execute();
    }
}
