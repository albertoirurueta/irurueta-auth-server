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

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Declares the authentication provider of the password-based sign-in, instead of the one Spring Security builds
 * from the {@link UserDetailsService} bean, to close a user enumeration.
 *
 * <p>The provider Spring Security builds checks the account status (locked, disabled, expired) <em>before</em> the
 * password, so a wrong password for, say, a disabled account answers "disabled": the page would reveal that the
 * account exists to anyone who types its username. This provider checks nothing before the password and the account
 * status after it ({@link AccountStatusUserDetailsChecker}), so a wrong password always gets the same generic answer,
 * known user or not, and a status message only appears to whoever proved they know the password.
 *
 * <p>Everything else is kept as the auto-built provider had it: the {@link PasswordEncoder}, the
 * {@link UserDetailsPasswordService} (which stores the stronger hash after a sign-in with an outdated encoding), a
 * {@link CompromisedPasswordChecker} when one bean of that type exists, and the hiding of unknown users behind a bad
 * credentials error. Being the only {@code AuthenticationProvider} bean, it is the one the global authentication
 * manager uses.
 */
@Configuration(proxyBeanMethods = false)
public class PasswordAuthenticationConfiguration {

    /**
     * Checks nothing before the password: the account status is only checked, and reported, after it.
     */
    static final UserDetailsChecker NO_PRE_AUTHENTICATION_CHECKS = user -> {
        // the account status is checked after the password, by the post-authentication checks
    };

    // tag::password-authentication-provider[]
    /**
     * Creates the authentication provider of the username and password sign-in.
     *
     * @param userDetailsService         loads the account by username.
     * @param userDetailsPasswordService stores the upgraded hash after a sign-in with an outdated encoding.
     * @param passwordEncoder            verifies the password, and tells when its hash needs upgrading.
     * @param compromisedPasswordChecker the compromised-password checker of Spring Security, when one is declared.
     * @return the provider, which checks the account status only after a correct password.
     */
    @Bean
    public DaoAuthenticationProvider passwordAuthenticationProvider(final UserDetailsService userDetailsService,
            final UserDetailsPasswordService userDetailsPasswordService, final PasswordEncoder passwordEncoder,
            final ObjectProvider<CompromisedPasswordChecker> compromisedPasswordChecker) {
        final var provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsPasswordService(userDetailsPasswordService);
        compromisedPasswordChecker.ifUnique(provider::setCompromisedPasswordChecker);
        provider.setHideUserNotFoundExceptions(true);
        provider.setPreAuthenticationChecks(NO_PRE_AUTHENTICATION_CHECKS);
        provider.setPostAuthenticationChecks(new AccountStatusUserDetailsChecker());
        return provider;
    }
    // end::password-authentication-provider[]
}
