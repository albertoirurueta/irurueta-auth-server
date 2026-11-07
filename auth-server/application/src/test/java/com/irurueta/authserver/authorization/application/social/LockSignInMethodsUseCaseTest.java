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
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import com.irurueta.authserver.authorization.domain.social.GeneratedPasswordRepository;
import com.irurueta.authserver.authorization.domain.social.SignInMethods;
import com.irurueta.authserver.authorization.domain.social.SignInMethodsLock;
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
 * Unit tests of {@link LockSignInMethodsUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class LockSignInMethodsUseCaseTest {

    /** Number of identities linked to the account. */
    private static final long IDENTITIES = 2;

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Port that serializes the removals of an account. */
    @Mock
    private SignInMethodsLock signInMethodsLock;

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

    /** Use case under test. */
    @InjectMocks
    private LockSignInMethodsUseCase useCase;

    /**
     * Verifies that the lock is taken before anything is counted, and that a generated password does not count.
     */
    @Test
    void execute_whenThePasswordIsGenerated_locksFirstAndCountsTheOtherMethods() {
        when(generatedPasswordRepository.isGenerated(userId)).thenReturn(true);
        when(federatedIdentityRepository.countByUser(userId)).thenReturn(IDENTITIES);
        when(passkeyRepository.existsForAccount(userId)).thenReturn(true);
        when(certificateBindingRepository.findByUser(userId)).thenReturn(List.of(new CertificateBinding(
                UUID.randomUUID(), userId, "b".repeat(CertificateBinding.FINGERPRINT_LENGTH), "CN=alice",
                Instant.parse("2026-01-01T10:00:00Z"))));

        final var methods = useCase.execute(userId);

        assertEquals(new SignInMethods(false, IDENTITIES, true, 1), methods);
        final var order = inOrder(signInMethodsLock, generatedPasswordRepository);
        order.verify(signInMethodsLock).lock(userId);
        order.verify(generatedPasswordRepository).isGenerated(userId);
    }

    /**
     * Verifies that a password of the user's own counts as a way to sign in.
     */
    @Test
    void execute_whenThePasswordIsTheUsers_countsIt() {
        when(generatedPasswordRepository.isGenerated(userId)).thenReturn(false);
        when(certificateBindingRepository.findByUser(userId)).thenReturn(List.of());

        assertEquals(new SignInMethods(true, 0, false, 0), useCase.execute(userId));
    }
}
