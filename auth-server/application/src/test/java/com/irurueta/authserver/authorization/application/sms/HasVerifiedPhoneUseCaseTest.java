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

package com.irurueta.authserver.authorization.application.sms;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link HasVerifiedPhoneUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class HasVerifiedPhoneUseCaseTest {

    /** Port that reads the verified phones. */
    @Mock
    private UserPhoneRepository userPhoneRepository;

    /** Use case under test. */
    @InjectMocks
    private HasVerifiedPhoneUseCase useCase;

    /**
     * Verifies that a user with a verified phone is reported, also as the enrolment query.
     */
    @Test
    void execute_whenPhoneIsVerified_returnsTrue() {
        final var userId = UUID.randomUUID();
        when(userPhoneRepository.findByUserId(userId)).thenReturn(
                Optional.of(new UserPhone(userId, new PhoneNumber("+34600000000"), Instant.EPOCH)));

        assertTrue(useCase.execute(userId));
        assertTrue(useCase.hasConfirmed(userId));
    }

    /**
     * Verifies that a user without a verified phone is reported as not enrolled.
     */
    @Test
    void execute_whenPhoneIsMissing_returnsFalse() {
        final var userId = UUID.randomUUID();
        when(userPhoneRepository.findByUserId(userId)).thenReturn(Optional.empty());

        assertFalse(useCase.execute(userId));
        assertFalse(useCase.hasConfirmed(userId));
    }
}
