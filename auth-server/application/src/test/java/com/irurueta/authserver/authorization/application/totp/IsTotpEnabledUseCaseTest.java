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
package com.irurueta.authserver.authorization.application.totp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link IsTotpEnabledUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class IsTotpEnabledUseCaseTest {

    /** Encrypted secret of the stored credentials. */
    private static final byte[] ENCRYPTED = {1, 2, 3};

    /** Port that stores the TOTP credentials. */
    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    /** Use case under test. */
    @InjectMocks
    private IsTotpEnabledUseCase useCase;

    /**
     * Verifies that a confirmed credential is enabled, through both entry points.
     */
    @Test
    void execute_whenCredentialIsConfirmed_returnsTrue() {
        final var userId = UUID.randomUUID();
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(credential(userId, true)));

        assertTrue(useCase.execute(userId));
        assertTrue(useCase.hasConfirmed(userId));
    }

    /**
     * Verifies that a pending enrolment is not enabled.
     */
    @Test
    void execute_whenEnrolmentIsPending_returnsFalse() {
        final var userId = UUID.randomUUID();
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(credential(userId, false)));

        assertFalse(useCase.execute(userId));
    }

    /**
     * Verifies that a user without a credential is not enabled.
     */
    @Test
    void hasConfirmed_whenThereIsNoCredential_returnsFalse() {
        final var userId = UUID.randomUUID();
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.empty());

        assertFalse(useCase.hasConfirmed(userId));
    }

    /**
     * Builds a credential.
     *
     * @param userId    identifier of the user.
     * @param confirmed whether it is confirmed.
     * @return the credential.
     */
    private static TotpCredential credential(final UUID userId, final boolean confirmed) {
        return new TotpCredential(userId, ENCRYPTED, confirmed, TotpCredential.NEVER_USED, Instant.EPOCH);
    }
}
