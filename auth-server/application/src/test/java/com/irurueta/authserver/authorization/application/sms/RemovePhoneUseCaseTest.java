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

import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RemovePhoneUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RemovePhoneUseCaseTest {

    /** Port that stores the verified phones. */
    @Mock
    private UserPhoneRepository userPhoneRepository;

    /** Port that stores the pending verifications. */
    @Mock
    private PhoneVerificationRepository phoneVerificationRepository;

    /** Use case under test. */
    @InjectMocks
    private RemovePhoneUseCase useCase;

    /**
     * Verifies that both the verified phone and the pending verification are removed.
     */
    @Test
    void execute_whenCalled_removesVerifiedAndPending() {
        final var userId = UUID.randomUUID();

        useCase.execute(userId);

        verify(userPhoneRepository).deleteByUserId(userId);
        verify(phoneVerificationRepository).deleteByUserId(userId);
    }
}
