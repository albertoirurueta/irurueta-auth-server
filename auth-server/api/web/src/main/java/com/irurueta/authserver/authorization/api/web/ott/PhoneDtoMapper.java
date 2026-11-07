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

import com.irurueta.authserver.authorization.api.web.v1.generated.model.PhoneEnrolmentResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.PhoneResponse;
import com.irurueta.authserver.authorization.application.sms.PhoneEnrolmentStarted;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import org.springframework.stereotype.Component;

/**
 * Maps the results of the phone use cases onto the DTOs generated from the contract. The number is never shown whole:
 * only its last digits are.
 */
@Component
public class PhoneDtoMapper {

    /** Number of trailing digits of the number that are shown. */
    static final int VISIBLE_DIGITS = 4;

    /** Character that replaces a hidden digit. */
    static final char HIDDEN_DIGIT = '*';

    /**
     * Maps a verified phone.
     *
     * @param phone the verified phone.
     * @return the phone with its number masked, such as {@code +*******1222}.
     */
    public PhoneResponse toResponse(final UserPhone phone) {
        return new PhoneResponse(mask(phone.phone().e164()), phone.verifiedAt());
    }

    /**
     * Maps a started enrolment.
     *
     * @param started the started enrolment.
     * @return the answer, with how long the code stays valid.
     */
    public PhoneEnrolmentResponse toResponse(final PhoneEnrolmentStarted started) {
        return new PhoneEnrolmentResponse(started.expiresIn());
    }

    /**
     * Hides every digit of an E.164 number but the last ones, keeping the {@code +} and the length.
     *
     * @param e164 the number.
     * @return the masked number.
     */
    private static String mask(final String e164) {
        final var hidden = Math.max(0, e164.length() - 1 - VISIBLE_DIGITS);
        return "+" + String.valueOf(HIDDEN_DIGIT).repeat(hidden) + e164.substring(1 + hidden);
    }
}
