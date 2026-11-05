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

package com.irurueta.authserver.authorization.domain.password;

/**
 * Port that hashes and checks passwords. The implementation chooses the algorithm; an encoded password carries its
 * own prefix so that older encodings can still be checked and upgraded. Never used with a {@code null} argument.
 */
public interface PasswordHasher {

    /**
     * Encodes a clear-text password (or a client secret) with the current algorithm.
     *
     * @param rawPassword the clear-text value.
     * @return the encoded value, including its encoding prefix.
     */
    String encode(CharSequence rawPassword);

    /**
     * Checks a clear-text password against an encoded one.
     *
     * @param rawPassword     the clear-text value.
     * @param encodedPassword the stored encoded value.
     * @return {@code true} when they match.
     */
    boolean matches(CharSequence rawPassword, String encodedPassword);

    /**
     * Tells whether a stored encoding is weaker than the current algorithm and should be replaced the next time
     * the clear-text password is known.
     *
     * @param encodedPassword the stored encoded value.
     * @return {@code true} when the password should be re-encoded.
     */
    boolean upgradeEncoding(String encodedPassword);
}
