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

package com.irurueta.authserver.resourceserver.api.web.security;

import java.util.Collection;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Maps the {@code roles} claim of a token onto authorities, for both JWT and opaque tokens.
 */
public final class BearerAuthorities {

    /** Name of the claim that carries the roles. */
    public static final String ROLES_CLAIM = "roles";

    /** Authority of an administrator. */
    public static final String ADMIN_ROLE = "ROLE_ADMIN";

    /** Prefix of a role authority. */
    private static final String ROLE_PREFIX = "ROLE_";

    /** Utility class: not meant to be instantiated. */
    private BearerAuthorities() {
    }

    /**
     * Maps role names to authorities, adding the {@code ROLE_} prefix when it is missing.
     *
     * @param roles role names; may be {@code null}.
     * @return the role authorities, empty when there are no roles.
     */
    public static Collection<GrantedAuthority> roleAuthorities(final Collection<String> roles) {
        if (roles == null) {
            return List.of();
        }
        return roles.stream()
                .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
    }

    /**
     * Tells whether the caller is an administrator.
     *
     * @param authentication the authenticated caller.
     * @return {@code true} when it holds {@code ROLE_ADMIN}.
     */
    public static boolean isAdministrator(final Authentication authentication) {
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> ADMIN_ROLE.equals(authority.getAuthority()));
    }
}
