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

package com.irurueta.authserver.authorization.infrastructure.persistence.ott;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.ott.JdbcOneTimeTokenService;

/**
 * Registers Spring Security's JDBC one-time token service, which stores the magic link tokens in the
 * {@code one_time_tokens} table instead of in memory. The login chain's {@code oneTimeTokenLogin} configurer finds it
 * as a bean.
 *
 * <p>The service keeps its own hourly cleanup of expired tokens. It is left enabled on purpose: disabling it with
 * {@code setCleanupCron(null)} does not stop the scheduler the constructor has already started, and an hourly delete
 * of expired rows is harmless next to the cleanup job of the application.</p>
 */
@Configuration(proxyBeanMethods = false)
public class OneTimeTokenServiceConfiguration {

    // tag::ott-token-service[]
    /**
     * Creates the one-time token service of the magic links.
     *
     * @param jdbcOperations JDBC operations of the application datasource.
     * @return the one-time token service.
     */
    @Bean
    public JdbcOneTimeTokenService oneTimeTokenService(final JdbcOperations jdbcOperations) {
        return new JdbcOneTimeTokenService(jdbcOperations);
    }
    // end::ott-token-service[]
}
