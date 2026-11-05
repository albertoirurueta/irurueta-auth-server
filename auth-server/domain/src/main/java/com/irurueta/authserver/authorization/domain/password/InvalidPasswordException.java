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

import java.util.List;

/**
 * The chosen password breaks the {@link PasswordPolicy}.
 */
public class InvalidPasswordException extends RuntimeException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /** The rules the password breaks. */
    private final transient List<PasswordViolation> violations;

    /**
     * Creates the exception.
     *
     * @param violations the rules the password breaks.
     */
    public InvalidPasswordException(final List<PasswordViolation> violations) {
        super("Password rejected by the policy: " + violations);
        this.violations = List.copyOf(violations);
    }

    /**
     * Gets the broken rules.
     *
     * @return the rules the password breaks, never empty.
     */
    public List<PasswordViolation> getViolations() {
        return violations;
    }
}
