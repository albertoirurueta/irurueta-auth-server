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

package com.irurueta.authserver.bff.api.web.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests of {@link ReturnToValidator}, mostly open-redirect attempts.
 */
class ReturnToValidatorTest {

    /** Validator with an exact path and a prefix allowed. */
    private final ReturnToValidator validator = new ReturnToValidator(
            new BffLoginProperties(List.of("/", "/index.html", "/orders/")));

    /**
     * Verifies that allowed relative paths, with or without query string and fragment, are accepted.
     *
     * @param returnTo the value to check.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/", "/index.html", "/index.html?tab=1", "/orders/", "/orders/42", "/orders/42?x=y#top"})
    void isAllowed_whenPathIsAllowed_returnsTrue(final String returnTo) {
        assertTrue(validator.isAllowed(returnTo), returnTo);
    }

    /**
     * Verifies that open-redirect payloads and paths not listed are rejected.
     *
     * @param returnTo the value to check.
     */
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "orders", "https://evil.example/", "http://evil.example", "//evil.example",
            "///evil.example", "/\\evil.example", "\\\\evil.example", "/orders/\\..\\x", "javascript:alert(1)",
            "/orders/../admin", "/orders/..", "/orders/./x", "/%2e%2e/admin", "/orders/%2F%2Fevil", "/other",
            "/ordersx", "/orders/\r\nSet-Cookie: a=b", "/orders/\u0000", "/orders/\t", " /orders/1"})
    void isAllowed_whenValueIsNotSafe_returnsFalse(final String returnTo) {
        assertFalse(validator.isAllowed(returnTo), String.valueOf(returnTo));
    }

    /**
     * Verifies that a query string cannot smuggle a path past the allow list.
     */
    @Test
    void isAllowed_whenQueryLooksLikeAllowedPath_checksThePathOnly() {
        assertFalse(validator.isAllowed("/other?next=/orders/1"));
        assertFalse(validator.isAllowed("/other#/orders/1"));
    }

    /**
     * Verifies the defaults used when nothing is configured.
     */
    @Test
    void constructor_whenNothingIsConfigured_allowsRootAndIndexOnly() {
        final var defaults = new ReturnToValidator(new BffLoginProperties(null));

        assertTrue(defaults.isAllowed("/"));
        assertTrue(defaults.isAllowed("/index.html"));
        assertFalse(defaults.isAllowed("/anything"));
        assertEquals(List.of("/", "/index.html"), new BffLoginProperties(List.of()).allowedReturnPaths());
    }
}
