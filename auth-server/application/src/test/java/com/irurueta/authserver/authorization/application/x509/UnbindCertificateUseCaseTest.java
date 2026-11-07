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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateNotFoundException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link UnbindCertificateUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class UnbindCertificateUseCaseTest {

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Identifier of the binding. */
    private final UUID id = UUID.randomUUID();

    /** Port that stores the bindings. */
    @Mock
    private CertificateBindingRepository certificateBindingRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Use case under test. */
    @InjectMocks
    private UnbindCertificateUseCase useCase;

    /**
     * Verifies that a binding of the account is deleted and audited.
     */
    @Test
    void execute_whenBindingExists_deletesAndAudits() {
        when(certificateBindingRepository.delete(id, userId)).thenReturn(true);

        useCase.execute(userId, "alice", id);

        verify(recordSecurityEventUseCase).execute(SecurityEventType.CERTIFICATE_UNBOUND, userId, "alice",
                id.toString());
    }

    /**
     * Verifies that a binding the account does not have is reported and not audited.
     */
    @Test
    void execute_whenBindingIsNotTheAccounts_throwsCertificateNotFoundException() {
        when(certificateBindingRepository.delete(id, userId)).thenReturn(false);

        assertThrows(CertificateNotFoundException.class, () -> useCase.execute(userId, "alice", id));

        verifyNoInteractions(recordSecurityEventUseCase);
    }
}
