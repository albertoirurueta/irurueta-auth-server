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

import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

/**
 * Registers the {@link CompromisedPasswordCheck} port. The check is enabled unless
 * {@code authserver.password.compromised-check.enabled} is {@code false}, in which case no password is reported as
 * compromised (for example in offline environments).
 */
@Configuration(proxyBeanMethods = false)
public class CompromisedPasswordConfiguration {

    /** Name of the property that switches the check on and off. */
    public static final String ENABLED_PROPERTY = "authserver.password.compromised-check.enabled";

    // tag::password-compromised-check[]
    /**
     * Creates the check backed by the Have I Been Pwned range API.
     *
     * @return the enabled check.
     */
    @Bean
    @ConditionalOnProperty(name = ENABLED_PROPERTY, havingValue = "true", matchIfMissing = true)
    public CompromisedPasswordCheck haveIBeenPwnedCompromisedPasswordCheck() {
        return new SpringCompromisedPasswordCheck(new HaveIBeenPwnedRestApiPasswordChecker());
    }

    /**
     * Creates the no-op check used when the property disables the check.
     *
     * @return a check that never reports a password as compromised.
     */
    @Bean
    @ConditionalOnProperty(name = ENABLED_PROPERTY, havingValue = "false")
    public CompromisedPasswordCheck noOpCompromisedPasswordCheck() {
        return password -> false;
    }
    // end::password-compromised-check[]
}
