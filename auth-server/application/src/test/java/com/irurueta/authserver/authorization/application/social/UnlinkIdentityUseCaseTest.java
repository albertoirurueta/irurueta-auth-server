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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityNotFoundException;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedLinkingPolicy;
import com.irurueta.authserver.authorization.domain.social.GeneratedPasswordRepository;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link UnlinkIdentityUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class UnlinkIdentityUseCaseTest {

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "a".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** Instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the signed-in user. */
    private final UUID userId = UUID.randomUUID();

    /** Identifier of the link. */
    private final UUID id = UUID.randomUUID();

    /** Port that stores the links. */
    @Mock
    private FederatedIdentityRepository federatedIdentityRepository;

    /** Port that remembers the accounts that only hold a generated password. */
    @Mock
    private GeneratedPasswordRepository generatedPasswordRepository;

    /** Port that reads the passkeys. */
    @Mock
    private PasskeyRepository passkeyRepository;

    /** Port that reads the bound certificates. */
    @Mock
    private CertificateBindingRepository certificateBindingRepository;

    /** Rules of linking and unlinking; the real behaviour is wanted. */
    @Spy
    private FederatedLinkingPolicy federatedLinkingPolicy = new FederatedLinkingPolicy();

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Use case under test. */
    @InjectMocks
    private UnlinkIdentityUseCase useCase;

    /**
     * Verifies that an identity is unlinked and audited while the account keeps a password of its own.
     */
    @Test
    void execute_whenAccountKeepsAPassword_deletesAndAudits() {
        givenIdentity(1, false, false, List.of());
        when(federatedIdentityRepository.delete(id, userId)).thenReturn(true);

        useCase.execute(userId, "alice", id);

        verify(recordSecurityEventUseCase).execute(SecurityEventType.IDENTITY_UNLINKED, userId, "alice", "google");
    }

    /**
     * Verifies that an identity is unlinked while another identity remains.
     */
    @Test
    void execute_whenAnotherIdentityRemains_deletesTheIdentity() {
        givenIdentity(2, true, false, List.of());
        when(federatedIdentityRepository.delete(id, userId)).thenReturn(true);

        useCase.execute(userId, "alice", id);

        verify(federatedIdentityRepository).delete(id, userId);
    }

    /**
     * Verifies that an identity is unlinked while a passkey remains.
     */
    @Test
    void execute_whenAPasskeyRemains_deletesTheIdentity() {
        givenIdentity(1, true, true, List.of());
        when(federatedIdentityRepository.delete(id, userId)).thenReturn(true);

        useCase.execute(userId, "alice", id);

        verify(federatedIdentityRepository).delete(id, userId);
    }

    /**
     * Verifies that an identity is unlinked while a certificate remains.
     */
    @Test
    void execute_whenACertificateRemains_deletesTheIdentity() {
        givenIdentity(1, true, false, List.of(new CertificateBinding(UUID.randomUUID(), userId, FINGERPRINT, "CN=a",
                NOW)));
        when(federatedIdentityRepository.delete(id, userId)).thenReturn(true);

        useCase.execute(userId, "alice", id);

        verify(federatedIdentityRepository).delete(id, userId);
    }

    /**
     * Verifies that the last way to sign in is never removed, and nothing is audited.
     */
    @Test
    void execute_whenIdentityIsTheLastMethod_throwsLastSignInMethodException() {
        givenIdentity(1, true, false, List.of());

        assertThrows(LastSignInMethodException.class, () -> useCase.execute(userId, "alice", id));

        verify(federatedIdentityRepository, never()).delete(id, userId);
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that an identity the account does not have is reported.
     */
    @Test
    void execute_whenIdentityIsNotTheAccounts_throwsFederatedIdentityNotFoundException() {
        when(federatedIdentityRepository.findByIdAndUser(id, userId)).thenReturn(Optional.empty());

        assertThrows(FederatedIdentityNotFoundException.class, () -> useCase.execute(userId, "alice", id));

        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that a link that disappears before it is deleted is reported and not audited.
     */
    @Test
    void execute_whenDeleteFindsNothing_throwsFederatedIdentityNotFoundException() {
        givenIdentity(1, false, false, List.of());
        when(federatedIdentityRepository.delete(id, userId)).thenReturn(false);

        assertThrows(FederatedIdentityNotFoundException.class, () -> useCase.execute(userId, "alice", id));

        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Arranges the account whose identity is being unlinked.
     *
     * @param identities   number of identities linked now, the one being removed included.
     * @param generated    whether the password is a generated one.
     * @param passkey      whether the account has a passkey.
     * @param certificates the bound certificates.
     */
    private void givenIdentity(final long identities, final boolean generated, final boolean passkey,
                               final List<CertificateBinding> certificates) {
        when(federatedIdentityRepository.findByIdAndUser(id, userId)).thenReturn(Optional.of(
                new FederatedIdentity(id, userId, IdentityProvider.GOOGLE, "subject", null, NOW, null)));
        when(generatedPasswordRepository.isGenerated(userId)).thenReturn(generated);
        when(federatedIdentityRepository.countByUser(userId)).thenReturn(identities);
        when(passkeyRepository.existsForAccount(userId)).thenReturn(passkey);
        when(certificateBindingRepository.findByUser(userId)).thenReturn(certificates);
    }
}
