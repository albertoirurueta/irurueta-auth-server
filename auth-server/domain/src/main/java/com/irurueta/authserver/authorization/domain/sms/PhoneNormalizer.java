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
 * Port that turns the phone number a user typed into E.164.
 */
public interface PhoneNormalizer {

    /**
     * Normalizes a number.
     *
     * @param input         what the user typed, possibly with spaces or punctuation.
     * @param defaultRegion ISO 3166-1 alpha-2 code of the region assumed when the input has no country prefix.
     * @return the number, or empty when the input is not a valid phone number.
     */
    Optional<PhoneNumber> normalize(String input, String defaultRegion);
}
