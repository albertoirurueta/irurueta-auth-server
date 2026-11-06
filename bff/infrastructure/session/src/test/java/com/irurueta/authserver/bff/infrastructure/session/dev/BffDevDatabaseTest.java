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

package com.irurueta.authserver.bff.infrastructure.session.dev;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.boot.jdbc.autoconfigure.JdbcConnectionDetails;

/**
 * Unit tests of {@link BffDevDatabase}.
 */
class BffDevDatabaseTest {

    /** Post processor under test. */
    private final BffDevDatabase postProcessor = new BffDevDatabase();

    /**
     * Verifies that the connection details (under the {@code dev} profile, the ones of Docker Compose) are redirected
     * to the {@code bff} database, keeping the rest of the URL and the credentials.
     */
    @Test
    void postProcessBeforeInitialization_whenBeanIsJdbcConnectionDetails_targetsBffDatabase() {
        final var compose = mock(JdbcConnectionDetails.class);
        when(compose.getJdbcUrl()).thenReturn("jdbc:postgresql://localhost:49153/authserver?ssl=false");
        when(compose.getUsername()).thenReturn("user");
        when(compose.getPassword()).thenReturn("secret-from-compose");
        when(compose.getDriverClassName()).thenReturn("org.postgresql.Driver");

        final var result = (JdbcConnectionDetails) postProcessor.postProcessBeforeInitialization(compose, "details");

        assertEquals("jdbc:postgresql://localhost:49153/bff?ssl=false", result.getJdbcUrl());
        assertEquals("user", result.getUsername());
        assertEquals("secret-from-compose", result.getPassword());
        assertEquals("org.postgresql.Driver", result.getDriverClassName());
    }

    /**
     * Verifies that a URL without query string is rewritten too.
     */
    @Test
    void postProcessBeforeInitialization_whenUrlHasNoQuery_targetsBffDatabase() {
        final var compose = mock(JdbcConnectionDetails.class);
        when(compose.getJdbcUrl()).thenReturn("jdbc:postgresql://localhost:5432/authserver");

        final var result = (JdbcConnectionDetails) postProcessor.postProcessBeforeInitialization(compose, "details");

        assertEquals("jdbc:postgresql://localhost:5432/bff", result.getJdbcUrl());
    }

    /**
     * Verifies that a bean other than connection details is left untouched.
     */
    @Test
    void postProcessBeforeInitialization_whenBeanIsNotJdbcConnectionDetails_returnsSameBean() {
        final var other = new Object();

        assertSame(other, postProcessor.postProcessBeforeInitialization(other, "other"));
    }
}
