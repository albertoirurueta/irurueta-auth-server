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

package com.irurueta.authserver.bff.dev;

import java.util.regex.Pattern;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.jdbc.autoconfigure.JdbcConnectionDetails;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Points the BFF at its own {@code bff} database when, in the {@code dev} profile, Spring Boot's Docker Compose
 * support supplies the datasource.
 *
 * <p>The root {@code compose.yaml} runs one PostgreSQL whose {@code POSTGRES_DB} is {@code authserver}, and the
 * connection details derived from the service always name that database; the init script creates the {@code bff}
 * one next to it. Connection details take precedence over {@code spring.datasource.*}, so the URL is rewritten here,
 * keeping host, port, user and password exactly as Compose reports them (nothing is committed). Connection details
 * that do not come from Compose (an explicit {@code BFF_DB_URL}) are left alone. It cannot live in {@code src/test}
 * because the packaged jar is run with the {@code dev} profile; it is inert elsewhere.
 */
@Component
@Profile("dev")
public class BffDevDatabase implements BeanPostProcessor {

    /** Name of the database of the BFF. */
    static final String DATABASE = "bff";

    /** Database segment of a PostgreSQL JDBC URL: what follows the authority, up to the query string. */
    private static final Pattern DATABASE_SEGMENT = Pattern.compile("^(jdbc:postgresql://[^/?]+/)[^?]*");

    @Override
    public Object postProcessBeforeInitialization(final Object bean, final String beanName) {
        if (bean instanceof JdbcConnectionDetails details && bean.getClass().getName().contains("DockerCompose")) {
            return new BffJdbcConnectionDetails(details);
        }
        return bean;
    }

    /**
     * Connection details of the compose PostgreSQL, addressing the {@code bff} database.
     *
     * @param delegate the details Compose supplied.
     */
    private record BffJdbcConnectionDetails(JdbcConnectionDetails delegate) implements JdbcConnectionDetails {

        @Override
        public String getUsername() {
            return delegate.getUsername();
        }

        @Override
        public String getPassword() {
            return delegate.getPassword();
        }

        @Override
        public String getJdbcUrl() {
            return DATABASE_SEGMENT.matcher(delegate.getJdbcUrl()).replaceFirst("$1" + DATABASE);
        }

        @Override
        public String getDriverClassName() {
            return delegate.getDriverClassName();
        }
    }
}
