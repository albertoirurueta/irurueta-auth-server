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

package com.irurueta.authserver.serviceclient.device;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DeviceFlowProperties}.
 */
class DeviceFlowPropertiesTest {

    /** The issuer. */
    private static final URI ISSUER = URI.create("http://auth.test");

    /**
     * Blank client and scope get the defaults.
     */
    @Test
    void constructor_whenClientAndScopeAreBlank_usesDefaults() {
        final var properties = new DeviceFlowProperties(ISSUER, " ", null, false);

        assertEquals(DeviceFlowProperties.DEFAULT_CLIENT_ID, properties.clientId());
        assertEquals(DeviceFlowProperties.DEFAULT_SCOPE, properties.scope());
    }

    /**
     * Explicit values are kept.
     */
    @Test
    void constructor_whenValuesAreSet_keepsThem() {
        final var properties = new DeviceFlowProperties(ISSUER, "other", "a b", true);

        assertEquals("other", properties.clientId());
        assertEquals("a b", properties.scope());
        assertEquals(ISSUER, properties.issuer());
    }

    /**
     * The issuer is mandatory.
     */
    @Test
    void constructor_whenIssuerIsMissing_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new DeviceFlowProperties(null, null, null, false));
    }
}
