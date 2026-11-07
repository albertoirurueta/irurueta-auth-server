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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ResolveCertificateLoginUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ResolveCertificateLoginUseCaseTest {

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "b".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Port that stores the bindings. */
    @Mock
    private CertificateBindingRepository certificateBindingRepository;

    /** Port that stores the accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Use case under test. */
    @InjectMocks
    private ResolveCertificateLoginUseCase useCase;

    /**
     * Verifies that a bound certificate resolves to its account.
     */
    @Test
    void execute_whenCertificateIsBound_returnsTheAccount() {
        final var account = new UserAccount(userId, "alice", "{noop}x", true, List.of());
        when(certificateBindingRepository.findByFingerprintSha256(FINGERPRINT)).thenReturn(Optional.of(
                new CertificateBinding(UUID.randomUUID(), userId, FINGERPRINT, "CN=alice", Instant.now())));
        when(userAccountRepository.findById(userId)).thenReturn(Optional.of(account));

        assertSame(account, useCase.execute(FINGERPRINT).orElseThrow());
    }

    /**
     * Verifies that an unbound certificate resolves to nothing.
     */
    @Test
    void execute_whenCertificateIsNotBound_returnsEmpty() {
        when(certificateBindingRepository.findByFingerprintSha256(FINGERPRINT)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(FINGERPRINT).isEmpty());

        verifyNoInteractions(userAccountRepository);
    }

    /**
     * Verifies that a malformed or missing fingerprint resolves to nothing without a lookup.
     */
    @Test
    void execute_whenFingerprintIsMalformed_returnsEmptyWithoutLookup() {
        assertTrue(useCase.execute(null).isEmpty());
        assertTrue(useCase.execute("ABC").isEmpty());
        assertTrue(useCase.execute(FINGERPRINT.toUpperCase(Locale.ROOT)).isEmpty());

        verifyNoInteractions(certificateBindingRepository, userAccountRepository);
    }
}
