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

package com.irurueta.authserver.authorization.application.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Unit tests of {@link PasskeyConfiguration}; the binding itself is covered by the integration tests of the boot
 * module.
 */
class PasskeyConfigurationTest {

    /**
     * Verifies that the configuration enables the binding of {@link PasskeyProperties}.
     */
    @Test
    void configuration_whenInspected_enablesPasskeyProperties() {
        assertNotNull(new PasskeyConfiguration());
        assertNotNull(PasskeyConfiguration.class.getAnnotation(Configuration.class));
        assertEquals(PasskeyProperties.class,
                PasskeyConfiguration.class.getAnnotation(EnableConfigurationProperties.class).value()[0]);
    }
}
