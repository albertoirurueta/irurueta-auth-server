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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.time.Duration;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DeviceFlowConfiguration}: the bean methods are called directly.
 */
class DeviceFlowConfigurationTest {

    /** The configuration. */
    private final DeviceFlowConfiguration configuration = new DeviceFlowConfiguration();

    /**
     * The sleeper accepts a zero wait.
     */
    @Test
    void deviceFlowSleeper_whenDurationIsZero_returnsImmediately() {
        final var sleeper = configuration.deviceFlowSleeper();

        assertDoesNotThrow(() -> sleeper.sleep(Duration.ZERO));
    }

    /**
     * The clock is UTC.
     */
    @Test
    void deviceFlowClock_whenCalled_returnsUtcClock() {
        assertEquals(ZoneOffset.UTC, configuration.deviceFlowClock().getZone());
    }

    /**
     * The output wraps the standard output.
     */
    @Test
    void deviceFlowOutput_whenCalled_returnsOutput() {
        assertNotNull(configuration.deviceFlowOutput());
    }

    /**
     * A trailing slash of the issuer is accepted.
     */
    @Test
    void deviceFlowRestClient_whenIssuerHasTrailingSlash_buildsClient() {
        assertNotNull(configuration.deviceFlowRestClient(
                new DeviceFlowProperties(URI.create("http://auth.test/"), null, null, false)));
        assertNotNull(configuration.deviceFlowRestClient(
                new DeviceFlowProperties(URI.create("http://auth.test"), null, null, false)));
    }
}
