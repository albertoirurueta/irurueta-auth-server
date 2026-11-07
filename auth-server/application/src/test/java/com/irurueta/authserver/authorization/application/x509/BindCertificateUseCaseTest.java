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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.x509.CertificateAlreadyBoundException;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
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
 * Unit tests of {@link BindCertificateUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class BindCertificateUseCaseTest {

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "c".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** Subject used by the tests. */
    private static final String SUBJECT = "CN=alice";

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Port that stores the bindings. */
    @Mock
    private CertificateBindingRepository certificateBindingRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private BindCertificateUseCase useCase;

    /**
     * Verifies that a new certificate is stored and audited.
     */
    @Test
    void execute_whenCertificateIsNew_storesAndAuditsIt() {
        when(clock.instant()).thenReturn(NOW);
        when(certificateBindingRepository.findByFingerprintSha256(FINGERPRINT)).thenReturn(Optional.empty());
        when(certificateBindingRepository.save(any(CertificateBinding.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final var result = useCase.execute(userId, "alice", FINGERPRINT, SUBJECT);

        final var captor = ArgumentCaptor.<CertificateBinding>captor();
        verify(certificateBindingRepository).save(captor.capture());
        assertSame(captor.getValue(), result);
        assertEquals(userId, result.userId());
        assertEquals(FINGERPRINT, result.fingerprintSha256());
        assertEquals(SUBJECT, result.subjectDn());
        assertEquals(NOW, result.createdAt());
        verify(recordSecurityEventUseCase).execute(SecurityEventType.CERTIFICATE_BOUND, userId, "alice",
                FINGERPRINT);
    }

    /**
     * Verifies that binding a certificate the account already has changes nothing.
     */
    @Test
    void execute_whenCertificateIsAlreadyBoundToTheAccount_returnsItWithoutChanges() {
        when(clock.instant()).thenReturn(NOW);
        final var existing = new CertificateBinding(UUID.randomUUID(), userId, FINGERPRINT, SUBJECT, NOW);
        when(certificateBindingRepository.findByFingerprintSha256(FINGERPRINT)).thenReturn(Optional.of(existing));

        assertSame(existing, useCase.execute(userId, "alice", FINGERPRINT, SUBJECT));

        verify(certificateBindingRepository, never()).save(any());
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that a certificate of another account is refused.
     */
    @Test
    void execute_whenCertificateBelongsToAnotherAccount_throwsCertificateAlreadyBoundException() {
        when(clock.instant()).thenReturn(NOW);
        when(certificateBindingRepository.findByFingerprintSha256(FINGERPRINT)).thenReturn(Optional.of(
                new CertificateBinding(UUID.randomUUID(), UUID.randomUUID(), FINGERPRINT, SUBJECT, NOW)));

        assertThrows(CertificateAlreadyBoundException.class,
                () -> useCase.execute(userId, "alice", FINGERPRINT, SUBJECT));

        verify(certificateBindingRepository, never()).save(any());
        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * Verifies that a malformed fingerprint is refused before anything is looked up.
     */
    @Test
    void execute_whenFingerprintIsMalformed_throwsIllegalArgumentException() {
        when(clock.instant()).thenReturn(NOW);

        assertThrows(IllegalArgumentException.class, () -> useCase.execute(userId, "alice", "nope", SUBJECT));

        verifyNoInteractions(certificateBindingRepository, recordSecurityEventUseCase);
    }
}
