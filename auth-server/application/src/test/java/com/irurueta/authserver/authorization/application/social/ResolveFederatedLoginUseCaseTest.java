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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.account.RegisterAccountUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.account.TokenGenerator;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedLinkingPolicy;
import com.irurueta.authserver.authorization.domain.social.FederatedLoginRefusedException;
import com.irurueta.authserver.authorization.domain.social.GeneratedPasswordRepository;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ResolveFederatedLoginUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ResolveFederatedLoginUseCaseTest {

    /** Subject used by the tests. */
    private static final String SUBJECT = "subject-1";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Encoded generated password. */
    private static final String ENCODED = "{bcrypt}generated";

    /** Instant of the first link. */
    private static final Instant LINKED_AT = Instant.parse("2025-12-01T10:00:00Z");

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the existing account. */
    private final UUID userId = UUID.randomUUID();

    /** Port that stores the links. */
    @Mock
    private FederatedIdentityRepository federatedIdentityRepository;

    /** Port that stores the accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Port that remembers the accounts that only hold a generated password. */
    @Mock
    private GeneratedPasswordRepository generatedPasswordRepository;

    /** Port that hashes the generated password. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Port that generates the secret of the generated password. */
    @Mock
    private TokenGenerator tokenGenerator;

    /** Rules of linking and provisioning; the real behaviour is wanted. */
    @Spy
    private FederatedLinkingPolicy federatedLinkingPolicy = new FederatedLinkingPolicy();

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private ResolveFederatedLoginUseCase useCase;

    /**
     * Fixes the current instant.
     */
    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(NOW);
    }

    /**
     * Verifies that a linked identity signs in its account and remembers the sign-in, keeping the stored e-mail
     * address when the provider reports none.
     */
    @Test
    void execute_whenIdentityIsLinked_returnsItsAccountAndRecordsTheSignIn() {
        final var account = account(true);
        final var link = new FederatedIdentity(UUID.randomUUID(), userId, IdentityProvider.GOOGLE, SUBJECT, EMAIL,
                LINKED_AT, null);
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.of(link));
        when(userAccountRepository.findById(userId)).thenReturn(Optional.of(account));
        when(federatedIdentityRepository.save(any(FederatedIdentity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final var result = useCase.execute(IdentityProvider.GOOGLE, SUBJECT, null, false);

        assertEquals(FederatedLoginOutcome.EXISTING, result.outcome());
        assertSame(account, result.account());
        assertEquals(EMAIL, result.identity().email());
        assertEquals(NOW, result.identity().lastLoginAt());
        assertEquals(LINKED_AT, result.identity().linkedAt());
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that the e-mail address a provider reports now replaces the stored one.
     */
    @Test
    void execute_whenLinkedIdentityReportsANewEmail_storesTheNewEmail() {
        final var link = new FederatedIdentity(UUID.randomUUID(), userId, IdentityProvider.GOOGLE, SUBJECT, EMAIL,
                LINKED_AT, null);
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.of(link));
        when(userAccountRepository.findById(userId)).thenReturn(Optional.of(account(true)));
        when(federatedIdentityRepository.save(any(FederatedIdentity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final var result = useCase.execute(IdentityProvider.GOOGLE, SUBJECT, "new@example.com", true);

        assertEquals("new@example.com", result.identity().email());
    }

    /**
     * Verifies that a link whose account is gone is refused.
     */
    @Test
    void execute_whenLinkedAccountIsMissing_throwsFederatedLoginRefusedException() {
        final var link = new FederatedIdentity(UUID.randomUUID(), userId, IdentityProvider.GOOGLE, SUBJECT, EMAIL,
                LINKED_AT, null);
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.of(link));
        when(userAccountRepository.findById(userId)).thenReturn(Optional.empty());

        assertThrows(FederatedLoginRefusedException.class,
                () -> useCase.execute(IdentityProvider.GOOGLE, SUBJECT, EMAIL, true));
    }

    /**
     * Verifies that an identity is linked to the account that has the same verified e-mail address.
     */
    @Test
    void execute_whenVerifiedEmailMatchesAVerifiedAccount_linksAndAudits() {
        final var account = account(true);
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.empty());
        when(userAccountRepository.findByEmail(EMAIL)).thenReturn(Optional.of(account));
        when(federatedIdentityRepository.save(any(FederatedIdentity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final var result = useCase.execute(IdentityProvider.GOOGLE, SUBJECT, EMAIL, true);

        assertEquals(FederatedLoginOutcome.LINKED, result.outcome());
        assertSame(account, result.account());
        assertEquals(userId, result.identity().userId());
        assertEquals(NOW, result.identity().linkedAt());
        verify(recordSecurityEventUseCase).execute(SecurityEventType.IDENTITY_LINKED, userId, "alice", "google");
        verify(userAccountRepository, never()).save(any());
    }

    /**
     * Verifies that an address the provider did not verify neither links nor provisions.
     */
    @Test
    void execute_whenEmailIsUnverified_throwsFederatedLoginRefusedException() {
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GITHUB, SUBJECT))
                .thenReturn(Optional.empty());

        assertThrows(FederatedLoginRefusedException.class,
                () -> useCase.execute(IdentityProvider.GITHUB, SUBJECT, EMAIL, false));

        verify(federatedIdentityRepository, never()).save(any());
        verify(userAccountRepository, never()).save(any());
    }

    /**
     * Verifies that a missing e-mail address neither links nor provisions.
     */
    @Test
    void execute_whenEmailIsMissing_throwsFederatedLoginRefusedException() {
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GITHUB, SUBJECT))
                .thenReturn(Optional.empty());

        assertThrows(FederatedLoginRefusedException.class,
                () -> useCase.execute(IdentityProvider.GITHUB, SUBJECT, null, true));
    }

    /**
     * Verifies that an account that never verified its address is not linked.
     */
    @Test
    void execute_whenMatchingAccountIsUnverified_throwsFederatedLoginRefusedException() {
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.empty());
        when(userAccountRepository.findByEmail(EMAIL)).thenReturn(Optional.of(account(false)));

        assertThrows(FederatedLoginRefusedException.class,
                () -> useCase.execute(IdentityProvider.GOOGLE, SUBJECT, EMAIL, true));

        verify(federatedIdentityRepository, never()).save(any());
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that an unknown verified address provisions an enabled account with a generated password, links
     * it and audits it.
     */
    @Test
    void execute_whenNoAccountHasTheEmail_provisionsAnAccount() {
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.APPLE, SUBJECT))
                .thenReturn(Optional.empty());
        when(userAccountRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(userAccountRepository.existsByUsername(EMAIL)).thenReturn(false);
        when(tokenGenerator.generate()).thenReturn("secret");
        when(passwordHasher.encode("secret")).thenReturn(ENCODED);
        when(federatedIdentityRepository.save(any(FederatedIdentity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final var result = useCase.execute(IdentityProvider.APPLE, SUBJECT, EMAIL, true);

        assertEquals(FederatedLoginOutcome.PROVISIONED, result.outcome());
        final var captor = ArgumentCaptor.<UserAccount>captor();
        verify(userAccountRepository).save(captor.capture());
        final var saved = captor.getValue();
        assertSame(saved, result.account());
        assertEquals(EMAIL, saved.username());
        assertEquals(ENCODED, saved.encodedPassword());
        assertTrue(saved.enabled());
        assertTrue(saved.emailVerified());
        assertEquals(List.of(RegisterAccountUseCase.DEFAULT_AUTHORITY), saved.authorities());
        assertEquals(saved.id(), result.identity().userId());
        verify(generatedPasswordRepository).markGenerated(saved.id());
        verify(recordSecurityEventUseCase).execute(SecurityEventType.IDENTITY_LINKED, saved.id(), EMAIL, "apple");
    }

    /**
     * Verifies that a taken username makes the provisioned account use the provider and its own identifier.
     */
    @Test
    void execute_whenUsernameIsTaken_provisionsAProviderPrefixedUsername() {
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GITHUB, SUBJECT))
                .thenReturn(Optional.empty());
        when(userAccountRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(userAccountRepository.existsByUsername(EMAIL)).thenReturn(true);
        when(tokenGenerator.generate()).thenReturn("secret");
        when(passwordHasher.encode("secret")).thenReturn(ENCODED);
        when(federatedIdentityRepository.save(any(FederatedIdentity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final var result = useCase.execute(IdentityProvider.GITHUB, SUBJECT, EMAIL, true);

        assertEquals("github-" + result.account().id(), result.account().username());
        assertNotEquals(EMAIL, result.account().username());
    }

    /**
     * Verifies that an address longer than a username can be makes the provisioned account use the provider and its
     * own identifier.
     */
    @Test
    void execute_whenEmailIsLongerThanAUsername_provisionsAProviderPrefixedUsername() {
        final var longEmail = "a".repeat(ResolveFederatedLoginUseCase.MAX_USERNAME_LENGTH) + "@example.com";
        when(federatedIdentityRepository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.empty());
        when(userAccountRepository.findByEmail(longEmail)).thenReturn(Optional.empty());
        when(userAccountRepository.existsByUsername(longEmail)).thenReturn(false);
        when(tokenGenerator.generate()).thenReturn("secret");
        when(passwordHasher.encode("secret")).thenReturn(ENCODED);
        when(federatedIdentityRepository.save(any(FederatedIdentity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final var result = useCase.execute(IdentityProvider.GOOGLE, SUBJECT, longEmail, true);

        assertEquals("google-" + result.account().id(), result.account().username());
    }

    /**
     * Builds the existing account.
     *
     * @param emailVerified whether the account verified its address.
     * @return the account.
     */
    private UserAccount account(final boolean emailVerified) {
        return new UserAccount(userId, "alice", "{noop}x", true, List.of("ROLE_USER"), EMAIL, emailVerified,
                UserAccount.DEFAULT_TENANT);
    }
}
