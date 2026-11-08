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
package com.irurueta.authserver.authorization.application.x509;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.application.social.LockSignInMethodsUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.social.FederatedLinkingPolicy;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import com.irurueta.authserver.authorization.domain.social.SignInMethods;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateNotFoundException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link UnbindCertificateUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class UnbindCertificateUseCaseTest {

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "a".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** Instant the certificate was bound. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Identifier of the binding. */
    private final UUID id = UUID.randomUUID();

    /** Port that stores the bindings. */
    @Mock
    private CertificateBindingRepository certificateBindingRepository;

    /** Locks and counts the sign-in methods of the account. */
    @Mock
    private LockSignInMethodsUseCase lockSignInMethodsUseCase;

    /** Rules of removing a sign-in method; the real behaviour is wanted. */
    @Spy
    private FederatedLinkingPolicy federatedLinkingPolicy = new FederatedLinkingPolicy();

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Use case under test. */
    @InjectMocks
    private UnbindCertificateUseCase useCase;

    /**
     * Verifies that a binding of the account is deleted and audited, after the lock is taken, while a password
     * remains.
     */
    @Test
    void execute_whenAPasswordRemains_locksDeletesAndAudits() {
        givenBinding(new SignInMethods(true, 0, false, 1));
        when(certificateBindingRepository.delete(id, userId)).thenReturn(true);

        useCase.execute(userId, "alice", id);

        final var order = inOrder(lockSignInMethodsUseCase, certificateBindingRepository);
        order.verify(lockSignInMethodsUseCase).execute(userId);
        order.verify(certificateBindingRepository).delete(id, userId);
        verify(recordSecurityEventUseCase).execute(SecurityEventType.CERTIFICATE_UNBOUND, userId, "alice",
                id.toString());
    }

    /**
     * Verifies that a certificate is unbound while another certificate remains.
     */
    @Test
    void execute_whenAnotherCertificateRemains_deletesTheBinding() {
        givenBinding(new SignInMethods(false, 0, false, 2));
        when(certificateBindingRepository.delete(id, userId)).thenReturn(true);

        useCase.execute(userId, "alice", id);

        verify(certificateBindingRepository).delete(id, userId);
    }

    /**
     * Verifies that a certificate is unbound while a linked identity remains.
     */
    @Test
    void execute_whenAnIdentityRemains_deletesTheBinding() {
        givenBinding(new SignInMethods(false, 1, false, 1));
        when(certificateBindingRepository.delete(id, userId)).thenReturn(true);

        useCase.execute(userId, "alice", id);

        verify(certificateBindingRepository).delete(id, userId);
    }

    /**
     * Verifies that the last way to sign in is never removed, and nothing is audited.
     */
    @Test
    void execute_whenCertificateIsTheLastMethod_throwsLastSignInMethodException() {
        givenBinding(new SignInMethods(false, 0, false, 1));

        assertThrows(LastSignInMethodException.class, () -> useCase.execute(userId, "alice", id));

        verify(certificateBindingRepository, never()).delete(any(), any());
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that a binding the account does not have is reported, never deleted and not audited.
     */
    @Test
    void execute_whenBindingIsNotTheAccounts_throwsCertificateNotFoundException() {
        when(lockSignInMethodsUseCase.execute(userId)).thenReturn(new SignInMethods(true, 0, false, 1));
        when(certificateBindingRepository.findByUser(userId)).thenReturn(List.of(
                new CertificateBinding(UUID.randomUUID(), userId, FINGERPRINT, "CN=other", NOW)));

        assertThrows(CertificateNotFoundException.class, () -> useCase.execute(userId, "alice", id));

        verify(certificateBindingRepository, never()).delete(any(), any());
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that a binding that disappears before it is deleted is reported and not audited.
     */
    @Test
    void execute_whenDeleteFindsNothing_throwsCertificateNotFoundException() {
        givenBinding(new SignInMethods(true, 0, false, 1));
        when(certificateBindingRepository.delete(id, userId)).thenReturn(false);

        assertThrows(CertificateNotFoundException.class, () -> useCase.execute(userId, "alice", id));

        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Arranges the account whose certificate is being unbound.
     *
     * @param methods the sign-in methods of the account now, the certificate being removed included.
     */
    private void givenBinding(final SignInMethods methods) {
        when(lockSignInMethodsUseCase.execute(userId)).thenReturn(methods);
        when(certificateBindingRepository.findByUser(userId)).thenReturn(List.of(
                new CertificateBinding(id, userId, FINGERPRINT, "CN=alice", NOW)));
    }
}
