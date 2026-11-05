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

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * Maps the domain {@link UserAccount} onto Spring Security's {@link UserDetails}.
 */
@Component
public class UserDetailsMapper {

    /**
     * Maps an account onto Spring Security's user details.
     *
     * @param account         the account.
     * @param encodedPassword the encoded password the details carry: the stored one, or the upgraded hash right
     *                        after a password upgrade.
     * @return the user details, disabled when the account is disabled and carrying the account's authorities.
     */
    public UserDetails toUserDetails(final UserAccount account, final String encodedPassword) {
        return User.withUsername(account.username())
                .password(encodedPassword)
                .disabled(!account.enabled())
                .authorities(AuthorityUtils.createAuthorityList(account.authorities()))
                .build();
    }
}
