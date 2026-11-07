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

import java.util.Optional;

/**
 * Port that tells the country of a phone number. The application layer has no phone-number library, so the SMS
 * adapter implements this port.
 */
public interface PhoneCountryResolver {

    /**
     * Finds the country of a number.
     *
     * @param phone the number.
     * @return the upper-case ISO 3166-1 alpha-2 code, or empty when the number belongs to no known region.
     */
    Optional<String> countryOf(PhoneNumber phone);
}
