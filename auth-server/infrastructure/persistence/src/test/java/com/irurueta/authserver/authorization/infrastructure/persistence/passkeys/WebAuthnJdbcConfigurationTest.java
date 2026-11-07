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

package com.irurueta.authserver.authorization.infrastructure.persistence.passkeys;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Unit tests of {@link WebAuthnJdbcConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class WebAuthnJdbcConfigurationTest {

    /** Configuration under test. */
    private final WebAuthnJdbcConfiguration configuration = new WebAuthnJdbcConfiguration();

    /** JDBC template given to the factory methods. */
    @Mock
    private JdbcTemplate jdbcTemplate;

    /**
     * Verifies that the user entity repository is created.
     */
    @Test
    void publicKeyCredentialUserEntityRepository_whenCalled_createsRepository() {
        assertNotNull(configuration.publicKeyCredentialUserEntityRepository(jdbcTemplate));
    }

    /**
     * Verifies that the credential repository is created.
     */
    @Test
    void userCredentialRepository_whenCalled_createsRepository() {
        assertNotNull(configuration.userCredentialRepository(jdbcTemplate));
    }
}
