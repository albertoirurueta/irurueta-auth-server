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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DeviceAuthorization}.
 */
class DeviceAuthorizationTest {

    /** The expires in. */
    private static final long EXPIRES_IN = 60L;

    /** The interval. */
    private static final long INTERVAL = 2L;

    /**
     * Valid values are kept.
     */
    @Test
    void constructor_whenValuesAreSet_keepsThem() {
        final var result = new DeviceAuthorization("dc", "uc", "uri", null, EXPIRES_IN, INTERVAL);

        assertEquals(EXPIRES_IN, result.expiresIn());
        assertEquals(INTERVAL, result.interval());
    }

    /**
     * Missing lifetime and interval get the documented defaults.
     */
    @Test
    void constructor_whenExpiresInAndIntervalAreMissing_usesDefaults() {
        final var result = new DeviceAuthorization("dc", "uc", "uri", null, 0L, -1L);

        assertEquals(DeviceAuthorization.DEFAULT_EXPIRES_IN_SECONDS, result.expiresIn());
        assertEquals(DeviceAuthorization.DEFAULT_INTERVAL_SECONDS, result.interval());
    }

    /**
     * Each mandatory member is checked.
     */
    @Test
    void constructor_whenMandatoryMemberIsMissing_throwsDeviceFlowException() {
        assertThrows(DeviceFlowException.class, () -> new DeviceAuthorization(null, "uc", "uri", null, 1L, 1L));
        assertThrows(DeviceFlowException.class, () -> new DeviceAuthorization("dc", " ", "uri", null, 1L, 1L));
        assertThrows(DeviceFlowException.class, () -> new DeviceAuthorization("dc", "uc", null, null, 1L, 1L));
    }

    /**
     * The device code is a secret and stays out of the description.
     */
    @Test
    void toString_whenCalled_hidesTheDeviceCode() {
        final var text = new DeviceAuthorization("secret-dc", "uc", "uri", null, 1L, 1L).toString();

        assertFalse(text.contains("secret-dc"));
        assertTrue(text.contains("uc"));
    }
}
