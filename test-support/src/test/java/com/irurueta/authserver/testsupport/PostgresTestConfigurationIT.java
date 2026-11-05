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

package com.irurueta.authserver.testsupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * Checks that {@link PostgresIT} wires the test context to the PostgreSQL container of
 * {@link PostgresTestConfiguration}.
 */
@PostgresIT
class PostgresTestConfigurationIT {

    /**
     * Server major version expected from {@link PostgresTestConfiguration#POSTGRES_IMAGE}.
     */
    private static final String EXPECTED_MAJOR_VERSION = "18";

    /**
     * Minimal application hosting the auto-configuration of the test context.
     */
    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {
    }

    /**
     * Data source created from the container's service connection.
     */
    @Autowired
    private DataSource dataSource;

    /**
     * Fails if the data source is unreachable or not backed by the expected PostgreSQL version.
     *
     * @throws SQLException if the database cannot be queried.
     */
    @Test
    void postgresContainer_whenContextStarts_dataSourceIsBackedByPostgres18() throws SQLException {
        try (var connection = dataSource.getConnection();
             var statement = connection.createStatement();
             var result = statement.executeQuery("SHOW server_version")) {
            assertTrue(result.next());
            assertTrue(result.getString(1).startsWith(EXPECTED_MAJOR_VERSION));
        }
    }

    /**
     * Fails if the image constant drifts from the version the test expects.
     */
    @Test
    void postgresImage_whenRead_namesMajorVersion18() {
        assertEquals("postgres:" + EXPECTED_MAJOR_VERSION, PostgresTestConfiguration.POSTGRES_IMAGE);
    }
}
