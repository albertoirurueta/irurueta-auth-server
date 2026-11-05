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

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * Spring Security {@link UserDetailsService} adapter over the {@link FindUserAccountUseCase} use case: it maps the
 * domain {@code UserAccount} onto Spring Security's {@link User}.
 */
@Component
@RequiredArgsConstructor
public class UserAccountUserDetailsService implements UserDetailsService {

    /** Use case that looks the account up. */
    private final FindUserAccountUseCase findUserAccountUseCase;

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        return findUserAccountUseCase.execute(username)
                .map(account -> User.withUsername(account.username())
                        .password(account.encodedPassword())
                        .disabled(!account.enabled())
                        .authorities(AuthorityUtils.createAuthorityList(account.authorities()))
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}
