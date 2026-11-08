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
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link StepUpLoginParameters}.
 */
class StepUpLoginParametersTest {

    /** Authentication context class asked for. */
    private static final String ACR_VALUES = "urn:irurueta:acr:mfa";

    /** Maximum age, in seconds, asked for. */
    private static final Long MAX_AGE = 300L;

    /** Values with the same fields are equal. */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var first = new StepUpLoginParameters(ACR_VALUES, MAX_AGE);
        final var second = new StepUpLoginParameters(ACR_VALUES, MAX_AGE);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first, new StepUpLoginParameters(ACR_VALUES, null));
    }

    /**
     * The values survive the serialization Spring Session JDBC applies to session attributes.
     *
     * @throws IOException            if the values cannot be written or read.
     * @throws ClassNotFoundException if the class cannot be found when read back.
     */
    @Test
    void equalsAndHashCode_whenSerializedAndRead_areEqual() throws IOException, ClassNotFoundException {
        final var parameters = new StepUpLoginParameters(ACR_VALUES, MAX_AGE);
        final var bytes = new ByteArrayOutputStream();
        try (var output = new ObjectOutputStream(bytes)) {
            output.writeObject(parameters);
        }

        try (var input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            assertEquals(parameters, input.readObject());
        }
    }
}
