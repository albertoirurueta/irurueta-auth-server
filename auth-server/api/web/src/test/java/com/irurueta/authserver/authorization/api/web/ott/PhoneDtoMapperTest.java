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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.application.sms.PhoneEnrolmentStarted;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link PhoneDtoMapper}. */
class PhoneDtoMapperTest {

    /** Mapper under test. */
    private final PhoneDtoMapper mapper = new PhoneDtoMapper();

    /** Only the last four digits of the number are shown. */
    @Test
    void toResponse_whenGivenAPhone_masksAllButTheLastFourDigits() {
        final var phone = new UserPhone(UUID.randomUUID(), new PhoneNumber("+34600111222"), Instant.EPOCH);

        final var response = mapper.toResponse(phone);

        assertEquals("+*******1222", response.maskedNumber());
        assertEquals(Instant.EPOCH, response.verifiedAt());
    }

    /** A number no longer than the visible digits is shown whole. */
    @Test
    void toResponse_whenTheNumberIsShort_showsItWhole() {
        final var phone = new UserPhone(UUID.randomUUID(), new PhoneNumber("+1234567"), Instant.EPOCH);

        assertEquals("+***4567", mapper.toResponse(phone).maskedNumber());
    }

    /** The enrolment answer carries how long the code is valid. */
    @Test
    void toResponse_whenGivenAStartedEnrolment_carriesTheLifetime() {
        final var lifetime = Duration.ofMinutes(10);

        assertEquals(lifetime, mapper.toResponse(new PhoneEnrolmentStarted(lifetime)).expiresIn());
    }
}
