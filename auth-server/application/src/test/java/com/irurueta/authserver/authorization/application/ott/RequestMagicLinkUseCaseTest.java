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
package com.irurueta.authserver.authorization.application.ott;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import java.net.URI;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Unit tests of {@link RequestMagicLinkUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RequestMagicLinkUseCaseTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** E-mail address of the user. */
    private static final String EMAIL = "alice@example.test";

    /** Link used by the tests. */
    private static final URI LINK = URI.create("https://auth.example.test/login/ott/confirm?token=t");

    /** Validity of the links. */
    private static final Duration LINK_TTL = Duration.ofMinutes(15);

    /** Use case that finds the address. */
    @Mock
    private ResolveOttDestinationUseCase resolveOttDestinationUseCase;

    /** Real policy of the tokens. */
    @Spy
    private OttPolicy ottPolicy = new OttPolicy(6, Duration.ofMinutes(10), LINK_TTL, 5);

    /** Publishes the delivery request. */
    @Mock
    private ApplicationEventPublisher eventPublisher;

    /** Use case under test. */
    @InjectMocks
    private RequestMagicLinkUseCase useCase;

    /**
     * Verifies that a known user's link is requested through an event, with the lifetime of a link.
     */
    @Test
    void execute_whenEmailDestinationExists_requestsTheLink() {
        when(resolveOttDestinationUseCase.execute(USERNAME, OttChannel.EMAIL))
                .thenReturn(Optional.of(new OttDestination(UUID.randomUUID(), OttChannel.EMAIL, EMAIL)));

        useCase.execute(USERNAME, LINK);

        verify(eventPublisher).publishEvent(new EmailLinkRequested(EMAIL, LINK, LINK_TTL));
    }

    /**
     * Verifies that nothing is requested for an unknown, disabled or unverified identifier.
     */
    @Test
    void execute_whenNoDestination_requestsNothing() {
        when(resolveOttDestinationUseCase.execute(USERNAME, OttChannel.EMAIL)).thenReturn(Optional.empty());

        useCase.execute(USERNAME, LINK);

        verifyNoInteractions(eventPublisher);
    }
}
