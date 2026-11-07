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
import com.irurueta.authserver.authorization.domain.sms.PhoneCountryResolver;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import java.util.Optional;
import lombok.RequiredArgsConstructor;

/**
 * {@link PhoneCountryResolver} over libphonenumber: the region of an E.164 number.
 */
@RequiredArgsConstructor
public class LibPhoneNumberCountryResolver implements PhoneCountryResolver {

    /** The libphonenumber entry point. */
    private final PhoneNumberUtil phoneNumberUtil;

    @Override
    public Optional<String> countryOf(final PhoneNumber phone) {
        try {
            final var parsed = phoneNumberUtil.parse(phone.e164(), null);
            return Optional.ofNullable(phoneNumberUtil.getRegionCodeForNumber(parsed))
                    .filter(region -> region.matches("[A-Z]{2}"));
        } catch (final NumberParseException e) {
            return Optional.empty();
        }
    }
}
