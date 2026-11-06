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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.totp.SecretGenerator;
import com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException;
import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link EnrollTotpUseCase}. The issuer is a constructor parameter of the use case, so it is built by
 * hand instead of with {@code @InjectMocks}.
 */
@ExtendWith(MockitoExtension.class)
class EnrollTotpUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Shared secret returned by the mocked generator. */
    private static final byte[] SECRET = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    /** Encrypted form of the secret returned by the mocked cipher. */
    private static final byte[] ENCRYPTED = {9, 9, 9};

    /** Port that stores the TOTP credentials. */
    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    /** Port that encrypts the secrets. */
    @Mock
    private TotpSecretCipher totpSecretCipher;

    /** Generator of the shared secrets. */
    @Mock
    private SecretGenerator secretGenerator;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    private EnrollTotpUseCase useCase;

    /**
     * Creates the use case.
     */
    @BeforeEach
    void setUp() {
        useCase = new EnrollTotpUseCase(totpCredentialRepository, totpSecretCipher, secretGenerator, clock, "Issuer");
    }

    /**
     * Verifies that an unconfirmed credential is stored encrypted and the URI returned.
     */
    @Test
    void execute_whenNothingIsEnabled_storesAnUnconfirmedCredentialAndReturnsTheUri() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.empty());
        when(secretGenerator.generate()).thenReturn(SECRET);
        when(totpSecretCipher.encrypt(SECRET)).thenReturn(ENCRYPTED);
        final var captor = ArgumentCaptor.<TotpCredential>captor();

        final var uri = useCase.execute(userId, "alice");

        verify(totpCredentialRepository).save(captor.capture());
        final var saved = captor.getValue();
        assertArrayEquals(ENCRYPTED, saved.encryptedSecret());
        assertFalse(saved.confirmed());
        assertEquals(TotpCredential.NEVER_USED, saved.lastUsedStep());
        assertTrue(uri.startsWith("otpauth://totp/Issuer:alice?secret="));
    }

    /**
     * Verifies that an earlier unconfirmed enrolment is replaced.
     */
    @Test
    void execute_whenAnUnconfirmedCredentialExists_replacesIt() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(
                new TotpCredential(userId, ENCRYPTED, false, TotpCredential.NEVER_USED, NOW)));
        when(secretGenerator.generate()).thenReturn(SECRET);
        when(totpSecretCipher.encrypt(SECRET)).thenReturn(ENCRYPTED);

        useCase.execute(userId, "alice");

        verify(totpCredentialRepository).save(org.mockito.ArgumentMatchers.any());
    }

    /**
     * Verifies that a user with a confirmed app cannot enrol another one.
     */
    @Test
    void execute_whenAlreadyConfirmed_throwsTotpAlreadyEnabledException() {
        final var userId = UUID.randomUUID();
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(
                new TotpCredential(userId, ENCRYPTED, true, 0L, NOW)));

        assertThrows(TotpAlreadyEnabledException.class, () -> useCase.execute(userId, "alice"));

        verify(totpCredentialRepository, never()).save(org.mockito.ArgumentMatchers.any());
    }
}
