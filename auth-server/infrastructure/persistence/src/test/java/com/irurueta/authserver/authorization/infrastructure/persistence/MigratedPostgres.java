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

package com.irurueta.authserver.authorization.infrastructure.persistence;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Test helper that starts one PostgreSQL container for the whole test JVM, migrates it with the Flyway migrations
 * of this module and hands out a data source. Integration tests share it and clean the tables they use.
 */
public final class MigratedPostgres {

    /** Docker image of the database; the same major version as {@code compose.yaml}. */
    private static final String POSTGRES_IMAGE = "postgres:18";

    /** Database container, started on first use and stopped by Testcontainers when the JVM exits. */
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer(
            DockerImageName.parse(POSTGRES_IMAGE));

    /** Data source of the migrated database, or {@code null} before the first use. */
    private static DataSource dataSource;

    /** Not instantiable. */
    private MigratedPostgres() {
    }

    /**
     * Returns the data source of the migrated database, starting and migrating it on first use.
     *
     * @return the data source.
     */
    public static synchronized DataSource dataSource() {
        if (dataSource == null) {
            POSTGRES.start();
            Flyway.configure()
                    .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                    .load()
                    .migrate();
            dataSource = new DriverManagerDataSource(
                    POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        }
        return dataSource;
    }
}
