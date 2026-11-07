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

package com.irurueta.authserver.authorization.api.web;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Unit tests of {@link AsyncConfiguration}.
 */
class AsyncConfigurationTest {

    /**
     * The configuration enables asynchronous methods.
     */
    @Test
    void class_whenInspected_enablesAsync() {
        final var configuration = new AsyncConfiguration();

        assertNotNull(configuration.getClass().getAnnotation(EnableAsync.class));
    }
}
