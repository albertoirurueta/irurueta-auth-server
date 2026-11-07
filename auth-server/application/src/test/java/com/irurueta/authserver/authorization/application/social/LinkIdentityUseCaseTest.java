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
package com.irurueta.authserver.authorization.application.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityAlreadyLinkedException;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link LinkIdentityUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class LinkIdentityUseCaseTest {

    /** Subject used by the tests. */
    private static final String SUBJECT = "subject-1";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the signed-in user. */
    private final UUID userId = UUID.randomUUID();

    /** Port that stores the links. */
    @Mock
    private FederatedIdentityRepository federatedIdentityRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private LinkIdentityUseCase useCase;

    /**
     * Verifies that a new identity is stored, with no sign-in yet, and audited.
     */
    @Test
    void execute_whenIdentityIsNotLinked_storesAndAuditsIt() {
        when(clock.instant()).thenReturn(NOW);
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.empty());
        when(federatedIdentityRepository.save(any(FederatedIdentity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final var result = useCase.execute(userId, "alice", IdentityProvider.GOOGLE, SUBJECT, EMAIL);

        final var captor = ArgumentCaptor.<FederatedIdentity>captor();
        verify(federatedIdentityRepository).save(captor.capture());
        assertSame(captor.getValue(), result);
        assertEquals(userId, result.userId());
        assertEquals(IdentityProvider.GOOGLE, result.provider());
        assertEquals(SUBJECT, result.subject());
        assertEquals(EMAIL, result.email());
        assertEquals(NOW, result.linkedAt());
        verify(recordSecurityEventUseCase).execute(SecurityEventType.IDENTITY_LINKED, userId, "alice", "google");
        final var order = inOrder(federatedIdentityRepository);
        order.verify(federatedIdentityRepository).lockSubject(IdentityProvider.GOOGLE, SUBJECT);
        order.verify(federatedIdentityRepository).findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT);
    }

    /**
     * Verifies that linking an identity the account already has changes nothing.
     */
    @Test
    void execute_whenIdentityIsAlreadyLinkedToTheAccount_returnsItWithoutChanges() {
        final var existing = identityOf(userId);
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.of(existing));

        assertSame(existing, useCase.execute(userId, "alice", IdentityProvider.GOOGLE, SUBJECT, EMAIL));

        verify(federatedIdentityRepository, never()).save(any());
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that an identity of another account is refused.
     */
    @Test
    void execute_whenIdentityBelongsToAnotherAccount_throwsFederatedIdentityAlreadyLinkedException() {
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.of(identityOf(UUID.randomUUID())));

        assertThrows(FederatedIdentityAlreadyLinkedException.class,
                () -> useCase.execute(userId, "alice", IdentityProvider.GOOGLE, SUBJECT, EMAIL));

        verify(federatedIdentityRepository, never()).save(any());
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Builds a link of an account.
     *
     * @param owner identifier of the account.
     * @return the link.
     */
    private static FederatedIdentity identityOf(final UUID owner) {
        return new FederatedIdentity(UUID.randomUUID(), owner, IdentityProvider.GOOGLE, SUBJECT, EMAIL, NOW, null);
    }
}
