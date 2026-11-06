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
package com.irurueta.authserver.authorization.api.web.login;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/**
 * Unit tests of {@link BrandingProperties}.
 */
class BrandingPropertiesTest {

    /** Application name used by the tests. */
    private static final String NAME = "Acme";

    /** Logo URL used by the tests. */
    private static final String LOGO = "/img/logo.svg";

    /** Footer text used by the tests. */
    private static final String FOOTER = "Acme Inc.";

    /**
     * Verifies that the given values are kept.
     */
    @Test
    void constructor_whenValuesAreGiven_keepsThem() {
        final var properties = new BrandingProperties(NAME, LOGO, FOOTER);

        assertEquals(NAME, properties.applicationName());
        assertEquals(LOGO, properties.logoUrl());
        assertEquals(FOOTER, properties.footerText());
    }

    /**
     * Verifies that missing values fall back to the defaults.
     */
    @Test
    void constructor_whenValuesAreMissing_appliesDefaults() {
        final var properties = new BrandingProperties(null, null, null);

        assertEquals(BrandingProperties.DEFAULT_APPLICATION_NAME, properties.applicationName());
        assertEquals("", properties.logoUrl());
        assertEquals("", properties.footerText());
    }

    /**
     * Verifies that blank values fall back to the defaults.
     */
    @Test
    void constructor_whenValuesAreBlank_appliesDefaults() {
        final var properties = new BrandingProperties(" ", " ", " ");

        assertEquals(BrandingProperties.DEFAULT_APPLICATION_NAME, properties.applicationName());
        assertEquals("", properties.logoUrl());
        assertEquals("", properties.footerText());
    }

    /**
     * Verifies that the properties bind from the {@code authserver.ui.branding} prefix.
     */
    @Test
    void bind_whenPrefixIsSet_bindsValues() {
        final var source = new MapConfigurationPropertySource(Map.of(
                "authserver.ui.branding.application-name", NAME,
                "authserver.ui.branding.logo-url", LOGO));

        final var properties = new Binder(source).bind("authserver.ui.branding", BrandingProperties.class).get();

        assertEquals(NAME, properties.applicationName());
        assertEquals(LOGO, properties.logoUrl());
        assertEquals("", properties.footerText());
    }
}
