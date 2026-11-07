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
package com.irurueta.authserver.authorization.infrastructure.persistence.social;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcSignInMethodsLock}, with the JDBC client mocked. The lock itself is taken against
 * PostgreSQL in {@link JdbcSignInMethodsLockIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcSignInMethodsLockTest {

    /** JDBC client that runs the statement. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Lock under test. */
    @InjectMocks
    private JdbcSignInMethodsLock lock;

    /**
     * Verifies that the account is locked with the advisory lock of its namespace, keyed by its identifier.
     */
    @Test
    void lock_whenCalled_takesTheAdvisoryLockOfTheAccount() {
        final var userId = UUID.randomUUID();

        lock.lock(userId);

        verify(client.sql(any(String.class))).params(JdbcSignInMethodsLock.SIGN_IN_METHODS_LOCK_NAMESPACE,
                userId.toString());
    }
}
