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
package com.irurueta.authserver.authorization.domain.ott;

/**
 * Port that generates the numeric codes users type.
 */
public interface OneTimeCodeGenerator {

    /**
     * Generates a random numeric code from a cryptographically secure source.
     *
     * @param digits number of digits, at least one.
     * @return the code, left-padded with zeros to exactly {@code digits} characters.
     * @throws IllegalArgumentException if {@code digits} is not positive.
     */
    String generate(int digits);
}
