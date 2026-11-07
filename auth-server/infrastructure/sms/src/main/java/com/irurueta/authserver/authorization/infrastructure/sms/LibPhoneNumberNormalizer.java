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

package com.irurueta.authserver.authorization.infrastructure.sms;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.irurueta.authserver.authorization.domain.sms.PhoneNormalizer;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.util.StringUtils;

/**
 * {@link PhoneNormalizer} backed by Google libphonenumber: accepts only valid numbers and never throws.
 */
@RequiredArgsConstructor
public class LibPhoneNumberNormalizer implements PhoneNormalizer {

    /** The libphonenumber entry point. */
    private final PhoneNumberUtil util;

    @Override
    public Optional<PhoneNumber> normalize(final String input, final String defaultRegion) {
        if (!StringUtils.hasText(input)) {
            return Optional.empty();
        }
        try {
            final var parsed = util.parse(input.trim(), defaultRegion);
            if (!util.isValidNumber(parsed)) {
                return Optional.empty();
            }
            return Optional.of(new PhoneNumber(util.format(parsed, PhoneNumberUtil.PhoneNumberFormat.E164)));
        } catch (final NumberParseException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
