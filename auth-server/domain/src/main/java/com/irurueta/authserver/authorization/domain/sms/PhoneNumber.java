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
package com.irurueta.authserver.authorization.domain.sms;

import java.util.regex.Pattern;

/**
 * A phone number in E.164 format. Only the shape is validated here; turning user input into E.164 is the job of a
 * {@link PhoneNormalizer}.
 *
 * @param e164 the number: a plus sign, then 7 to 15 digits, the first of which is not zero.
 */
public record PhoneNumber(String e164) {

    /** Shape of an E.164 number. */
    private static final Pattern E164 = Pattern.compile("^\\+[1-9]\\d{6,14}$");

    /**
     * Validates the number.
     *
     * @throws IllegalArgumentException if the value is missing or not in E.164 shape.
     */
    public PhoneNumber {
        if (e164 == null || !E164.matcher(e164).matches()) {
            throw new IllegalArgumentException("e164 must be an E.164 phone number");
        }
    }
}
