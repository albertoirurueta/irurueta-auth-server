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
import com.irurueta.authserver.authorization.application.password.UpgradePasswordHashUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * Spring Security {@link UserDetailsService} adapter over the {@link FindUserAccountUseCase} use case: it maps the
 * domain {@code UserAccount} onto Spring Security's {@link User}. As a {@link UserDetailsPasswordService} it also
 * stores the stronger hash that the authentication provider produces after a successful sign-in with an outdated
 * encoding, through the {@link UpgradePasswordHashUseCase} use case.
 */
@Component
@RequiredArgsConstructor
public class UserAccountUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

    /** Use case that looks the account up. */
    private final FindUserAccountUseCase findUserAccountUseCase;

    /** Use case that stores the upgraded hash. */
    private final UpgradePasswordHashUseCase upgradePasswordHashUseCase;

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        return findUserAccountUseCase.execute(username)
                .map(account -> toUserDetails(account, account.encodedPassword()))
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    // tag::password-upgrade[]
    @Override
    public UserDetails updatePassword(final UserDetails user, final String newPassword) {
        final var account = findUserAccountUseCase.execute(user.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + user.getUsername()));
        upgradePasswordHashUseCase.replaceHash(account, newPassword);
        return toUserDetails(account, newPassword);
    }
    // end::password-upgrade[]

    /**
     * Maps an account onto Spring Security's user details.
     *
     * @param account         the account.
     * @param encodedPassword the encoded password the details carry.
     * @return the user details.
     */
    private static UserDetails toUserDetails(final UserAccount account, final String encodedPassword) {
        return User.withUsername(account.username())
                .password(encodedPassword)
                .disabled(!account.enabled())
                .authorities(AuthorityUtils.createAuthorityList(account.authorities()))
                .build();
    }
}
