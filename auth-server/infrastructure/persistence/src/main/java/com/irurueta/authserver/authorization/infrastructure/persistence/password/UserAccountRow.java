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

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.List;
import java.util.UUID;

/**
 * Columns of a user row joined with its encoded password, before the authorities, which live in a table of their
 * own, are loaded.
 *
 * @param id            identifier of the user.
 * @param username      name the user signs in with.
 * @param password      encoded password.
 * @param enabled       whether the account is enabled.
 * @param email         e-mail address, or {@code null} when the user has none.
 * @param emailVerified whether the e-mail address was verified.
 * @param tenant        tenant the user belongs to.
 */
public record UserAccountRow(UUID id, String username, String password, boolean enabled, String email,
                             boolean emailVerified, String tenant) {

    /**
     * Completes the row into an account.
     *
     * @param authorities authorities of the user, loaded separately.
     * @return the account.
     */
    public UserAccount toUserAccount(final List<String> authorities) {
        return new UserAccount(id, username, password, enabled, authorities, email, emailVerified, tenant);
    }
}
