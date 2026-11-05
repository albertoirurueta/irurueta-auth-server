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

package com.irurueta.authserver.authorization.api.web.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

/**
 * Unit tests of {@link UserDetailsMapper}.
 */
class UserDetailsMapperTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Encoded password stored on the account; not a real credential. */
    private static final String ENCODED_PASSWORD = "{noop}encoded";

    /** Encoded password passed to the mapper; not a real credential. */
    private static final String OTHER_ENCODED_PASSWORD = "{argon2}upgraded";

    /** Authority used by the tests. */
    private static final String ROLE_USER = "ROLE_USER";

    /** Mapper under test. */
    private final UserDetailsMapper mapper = new UserDetailsMapper();

    /**
     * Verifies that an enabled account is mapped to enabled details with its authorities.
     */
    @Test
    void toUserDetails_whenAccountIsEnabled_returnsEnabledUserWithAuthorities() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true, List.of(ROLE_USER));

        final var user = mapper.toUserDetails(account, ENCODED_PASSWORD);

        assertEquals(USERNAME, user.getUsername());
        assertEquals(ENCODED_PASSWORD, user.getPassword());
        assertTrue(user.isEnabled());
        assertEquals(List.of(ROLE_USER), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    /**
     * Verifies that a disabled account is mapped to disabled details.
     */
    @Test
    void toUserDetails_whenAccountIsDisabled_returnsDisabledUser() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, false, List.of());

        final var user = mapper.toUserDetails(account, ENCODED_PASSWORD);

        assertFalse(user.isEnabled());
        assertTrue(user.getAuthorities().isEmpty());
    }

    /**
     * Verifies that the details carry the given password rather than the stored one.
     */
    @Test
    void toUserDetails_whenPasswordDiffersFromStoredOne_carriesGivenPassword() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true, List.of(ROLE_USER));

        final var user = mapper.toUserDetails(account, OTHER_ENCODED_PASSWORD);

        assertEquals(OTHER_ENCODED_PASSWORD, user.getPassword());
    }
}
