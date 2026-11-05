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
 * Port that tells whether a password is known to have leaked in a data breach. An implementation never sends the
 * clear-text password anywhere and must decide what to answer when its source is unreachable.
 */
public interface CompromisedPasswordCheck {

    /**
     * Checks a password against a list of leaked passwords.
     *
     * @param password the clear-text password.
     * @return {@code true} when the password is known to be compromised.
     */
    boolean isCompromised(String password);
}
