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
package com.irurueta.authserver.authorization.domain.ott;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of the enumeration {@link OttChannel}, whose names are stored in the database and must not change.
 */
class OttChannelTest {

    /**
     * Verifies the channels.
     */
    @Test
    void values_whenListed_areEmailAndSms() {
        assertArrayEquals(new OttChannel[] {OttChannel.EMAIL, OttChannel.SMS}, OttChannel.values());
    }
}
