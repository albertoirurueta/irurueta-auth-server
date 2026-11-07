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

import static org.junit.jupiter.api.Assertions.assertEquals;
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

/** Unit tests of {@link FindUserPhoneUseCase}. */
@ExtendWith(MockitoExtension.class)
class FindUserPhoneUseCaseTest {

    /** Test fixture. */
    private static final UUID USER_ID = UUID.randomUUID();

    /** Port that reads the verified phones. */
    @Mock
    private UserPhoneRepository userPhoneRepository;

    /** Use case under test. */
    @InjectMocks
    private FindUserPhoneUseCase useCase;

    /** The verified phone of the user is returned. */
    @Test
    void execute_whenUserHasPhone_returnsIt() {
        final var phone = new UserPhone(USER_ID, new PhoneNumber("+34600111222"), Instant.EPOCH);
        when(userPhoneRepository.findByUserId(USER_ID)).thenReturn(Optional.of(phone));

        assertEquals(Optional.of(phone), useCase.execute(USER_ID));
    }

    /** A user without a phone gets an empty answer. */
    @Test
    void execute_whenUserHasNoPhone_returnsEmpty() {
        when(userPhoneRepository.findByUserId(USER_ID)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(USER_ID).isEmpty());
    }
}
