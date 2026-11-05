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

package com.irurueta.authserver.authorization.domain.password;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;
import static com.irurueta.authserver.authorization.domain.Preconditions.requireTextIfPresent;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * A user that can sign in with a password.
 *
 * @param id              unique identifier of the account.
 * @param username        name the user signs in with.
 * @param encodedPassword password hash, including its encoding prefix; never a clear-text password.
 * @param enabled         whether the account can be used to sign in.
 * @param authorities     authorities (roles and permissions) granted to the account.
 * @param email           e-mail address of the user; {@code null} when the account has none.
 * @param emailVerified   whether the user proved to own the e-mail address.
 * @param tenant          tenant the account belongs to; feeds the {@code tenant} claim of issued tokens.
 */
public record UserAccount(
        UUID id, String username, String encodedPassword, boolean enabled, List<String> authorities, String email,
        boolean emailVerified, String tenant) {

    /** Tenant of the accounts that do not name one. */
    public static final String DEFAULT_TENANT = "default";

    /**
     * Creates an account without an e-mail address, in the default tenant.
     *
     * @param id              unique identifier of the account.
     * @param username        name the user signs in with.
     * @param encodedPassword password hash, including its encoding prefix.
     * @param enabled         whether the account can be used to sign in.
     * @param authorities     authorities granted to the account.
     */
    public UserAccount(final UUID id, final String username, final String encodedPassword, final boolean enabled,
                       final List<String> authorities) {
        this(id, username, encodedPassword, enabled, authorities, null, false, DEFAULT_TENANT);
    }

    /**
     * Validates the account and defensively copies its authorities.
     *
     * @throws IllegalArgumentException if the id is null, the username or encoded password is null or blank, or
     *                                  the authorities are null or contain a null element, the e-mail is blank or
     *                                  the tenant is null or blank.
     */
    public UserAccount {
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        requireText(username, "username");
        requireText(encodedPassword, "encodedPassword");
        if (authorities == null || authorities.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("authorities must not be null or contain null elements");
        }
        requireTextIfPresent(email, "email");
        requireText(tenant, "tenant");
        authorities = List.copyOf(authorities);
    }
}
