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
package com.irurueta.authserver.authorization.domain;

/**
 * Argument checks shared by the domain models. The domain depends on nothing but the JDK, so it cannot use
 * Spring's {@code StringUtils}; these helpers keep the null-or-blank branch in one place instead of in every
 * compact constructor.
 */
public final class Preconditions {

    /**
     * Not instantiable: a holder of static helpers.
     */
    private Preconditions() {
    }

    /**
     * Tells whether a text is missing.
     *
     * @param value value to check.
     * @return {@code true} when the value is {@code null}, empty or only whitespace.
     */
    public static boolean isBlank(final String value) {
        return value == null || value.isBlank();
    }

    /**
     * Rejects a null or blank text.
     *
     * @param value value to check.
     * @param name  name of the value, for the message.
     * @return the value, so a check can be used inline.
     * @throws IllegalArgumentException if the value is {@code null}, empty or only whitespace.
     */
    public static String requireText(final String value, final String name) {
        if (isBlank(value)) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }

    /**
     * Rejects a blank text but accepts a missing one, for an optional value.
     *
     * @param value value to check, or {@code null}.
     * @param name  name of the value, for the message.
     * @return the value.
     * @throws IllegalArgumentException if the value is empty or only whitespace.
     */
    public static String requireTextIfPresent(final String value, final String name) {
        return value == null ? null : requireText(value, name);
    }
}
