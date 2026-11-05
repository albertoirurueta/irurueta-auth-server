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

package com.irurueta.authserver.authorization.infrastructure.persistence.password;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link UserAccountRow}.
 */
class UserAccountRowTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Encoded password used by the tests; not a real credential. */
    private static final String ENCODED_PASSWORD = "{noop}encoded";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Tenant used by the tests. */
    private static final String TENANT = "acme";

    /** Authority used by the tests. */
    private static final String ROLE_USER = "ROLE_USER";

    /**
     * Verifies that the row and the given authorities make up the account.
     */
    @Test
    void toUserAccount_whenAuthoritiesAreGiven_returnsCompleteAccount() {
        final var id = UUID.randomUUID();
        final var row = new UserAccountRow(id, USERNAME, ENCODED_PASSWORD, false, EMAIL, true, TENANT);

        assertEquals(new UserAccount(id, USERNAME, ENCODED_PASSWORD, false, List.of(ROLE_USER), EMAIL, true, TENANT),
                row.toUserAccount(List.of(ROLE_USER)));
    }
}
