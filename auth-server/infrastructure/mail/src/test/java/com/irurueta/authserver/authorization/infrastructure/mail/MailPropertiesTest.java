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

package com.irurueta.authserver.authorization.infrastructure.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Locale;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link MailProperties}.
 */
class MailPropertiesTest {

    /** Sender used by the tests. */
    private static final String SENDER = "auth@example.com";

    /**
     * Missing values receive the defaults.
     */
    @Test
    void constructor_whenValuesAreMissing_appliesDefaults() {
        final var properties = new MailProperties(" ", null, null);

        assertEquals(MailProperties.DEFAULT_FROM, properties.from());
        assertEquals(MailProperties.DEFAULT_BASE_URL, properties.baseUrl());
        assertEquals(Locale.ENGLISH, properties.locale());
    }

    /**
     * Given values are kept and a trailing slash is removed.
     */
    @Test
    void constructor_whenBaseUrlHasTrailingSlash_removesIt() {
        final var properties = new MailProperties(SENDER, "https://a.example.com/", Locale.FRENCH);

        assertEquals(SENDER, properties.from());
        assertEquals("https://a.example.com", properties.baseUrl());
        assertEquals(Locale.FRENCH, properties.locale());
    }
}
