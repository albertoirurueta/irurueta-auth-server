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
package com.irurueta.authserver.authorization.application.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.password.PasswordViolation;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Tests {@link PasswordPolicyConfiguration}.
 */
class PasswordPolicyConfigurationTest {

    /** Configuration under test. */
    private final PasswordPolicyConfiguration configuration = new PasswordPolicyConfiguration();

    /**
     * The bean is the domain's policy: it rejects a short password and accepts a long enough one.
     */
    @Test
    void passwordPolicy_whenCreated_appliesTheDomainRules() {
        final var policy = configuration.passwordPolicy();

        assertEquals(List.of(PasswordViolation.TOO_SHORT), policy.violations("alice", "short"));
        assertTrue(policy.violations("alice", "correct horse battery staple").isEmpty());
    }
}
