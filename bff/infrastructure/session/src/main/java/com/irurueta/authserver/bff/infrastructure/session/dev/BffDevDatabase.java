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
 * keeping host, port, user and password exactly as Compose reports them (nothing is committed).
 *
 * <p>Every {@link JdbcConnectionDetails} bean is wrapped, with no test of where it comes from: under the {@code dev}
 * profile there is exactly one, the one of Docker Compose, because Spring Boot's own properties-based connection
 * details back off when Compose provides some. This class is inert outside the {@code dev} profile.
 *
 * <p>It is development-only code in {@code src/main}, like {@code DevDataInitializer} and
 * {@code DevKeyEncryptionSecret} of the authorization server, and for the same reason: it cannot live in
 * {@code src/test}, because the end-to-end tests run the packaged jar, and so does anyone starting the BFF with the
 * {@code dev} profile ({@code java -jar} or {@code spring-boot:run}); a packaged jar contains no test classes.
 */
@Component
@Profile("dev")
public class BffDevDatabase implements BeanPostProcessor {

    /** Name of the database of the BFF. */
    static final String DATABASE = "bff";

    /** Database segment of a PostgreSQL JDBC URL: what follows the authority, up to the query string. */
    private static final Pattern DATABASE_SEGMENT = Pattern.compile("^(jdbc:postgresql://[^/?]+/)[^?]*");

    /**
     * Wraps the JDBC connection details so that they address the {@code bff} database; any other bean is returned
     * unchanged.
     *
     * @param bean     the bean being initialized.
     * @param beanName the name of the bean.
     * @return the wrapped connection details, or the bean itself.
     */
    @Override
    public Object postProcessBeforeInitialization(final Object bean, final String beanName) {
        if (bean instanceof JdbcConnectionDetails details) {
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
