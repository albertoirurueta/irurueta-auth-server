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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ListCertificatesUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ListCertificatesUseCaseTest {

    /** Port that stores the bindings. */
    @Mock
    private CertificateBindingRepository certificateBindingRepository;

    /** Use case under test. */
    @InjectMocks
    private ListCertificatesUseCase useCase;

    /**
     * Verifies that the bindings of the account are answered as the port lists them.
     */
    @Test
    void execute_whenTheAccountHasCertificates_returnsThem() {
        final var userId = UUID.randomUUID();
        final var bindings = List.of(new CertificateBinding(UUID.randomUUID(), userId,
                "c".repeat(CertificateBinding.FINGERPRINT_LENGTH), "CN=alice", Instant.parse("2026-01-01T10:00:00Z")));
        when(certificateBindingRepository.findByUser(userId)).thenReturn(bindings);

        assertSame(bindings, useCase.execute(userId));
    }
}
