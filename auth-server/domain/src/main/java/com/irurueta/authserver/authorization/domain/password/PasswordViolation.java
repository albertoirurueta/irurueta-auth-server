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
 * A rule of the {@link PasswordPolicy} that a candidate password breaks.
 */
public enum PasswordViolation {

    /** The password is shorter than {@link PasswordPolicy#MIN_LENGTH} characters. */
    TOO_SHORT,

    /** The password is longer than {@link PasswordPolicy#MAX_LENGTH} characters. */
    TOO_LONG,

    /** The password contains the username of the account. */
    CONTAINS_USERNAME
}
