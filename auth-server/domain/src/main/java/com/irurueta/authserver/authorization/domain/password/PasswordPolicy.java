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

import static com.irurueta.authserver.authorization.domain.Preconditions.isBlank;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Password rules in the style of NIST SP 800-63B: a minimum and a maximum length, no composition rules (no required
 * digits, symbols or upper-case letters) and a password that does not contain the username. The policy has no state,
 * so a single instance can be shared.
 */
public final class PasswordPolicy {

    /** Minimum number of characters of a password. */
    public static final int MIN_LENGTH = 12;

    /** Maximum number of characters of a password. */
    public static final int MAX_LENGTH = 128;

    // tag::password-policy[]
    /**
     * Finds the rules a candidate password breaks.
     *
     * @param username name of the account the password is for; the username rule is skipped when it is {@code null}
     *                 or blank.
     * @param password the candidate password; {@code null} is treated as an empty password.
     * @return the broken rules, empty when the password is acceptable.
     */
    public List<PasswordViolation> violations(final String username, final String password) {
        final var candidate = password == null ? "" : password;
        final var violations = new ArrayList<PasswordViolation>();
        final var length = candidate.codePointCount(0, candidate.length());
        if (length < MIN_LENGTH) {
            violations.add(PasswordViolation.TOO_SHORT);
        }
        if (length > MAX_LENGTH) {
            violations.add(PasswordViolation.TOO_LONG);
        }
        if (!isBlank(username)
                && candidate.toLowerCase(Locale.ROOT).contains(username.toLowerCase(Locale.ROOT))) {
            violations.add(PasswordViolation.CONTAINS_USERNAME);
        }
        return List.copyOf(violations);
    }

    /**
     * Tells whether a candidate password follows every rule.
     *
     * @param username name of the account the password is for.
     * @param password the candidate password.
     * @return {@code true} when no rule is broken.
     */
    public boolean isValid(final String username, final String password) {
        return violations(username, password).isEmpty();
    }
    // end::password-policy[]
}
