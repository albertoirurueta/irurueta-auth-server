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
package com.irurueta.authserver.authorization;

import java.util.ArrayList;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

/**
 * Points the endpoints of the social login registrations at {@link FakeIdentityProviders}. It replaces the
 * repository after the application built it, so the registrations (issuer, scopes, client authentication, the client
 * secret of Apple) stay the ones the application derives from its settings and only the addresses change. Package
 * private on purpose: the test classes import it, and Spring's test context detects only non-private configuration
 * classes.
 */
@TestConfiguration(proxyBeanMethods = false)
class FakeIdentityProvidersConfiguration {

    /** Not instantiated by anybody: the configuration only declares a static bean method. */
    private FakeIdentityProvidersConfiguration() {
    }

    /**
     * Declares the post processor; static so it exists before the beans it processes.
     *
     * @return the post processor.
     */
    @Bean
    static BeanPostProcessor fakeProviderEndpoints() {
        return new RegistrationRedirector();
    }

    /**
     * Rewrites the endpoints of the registrations of the application.
     */
    static final class RegistrationRedirector implements BeanPostProcessor {

        @Override
        public Object postProcessAfterInitialization(final Object bean, final String beanName) {
            if (bean instanceof final InMemoryClientRegistrationRepository repository) {
                final var redirected = new ArrayList<ClientRegistration>();
                repository.forEach(registration -> redirected.add(FakeIdentityProviders.redirect(registration)));
                return new InMemoryClientRegistrationRepository(redirected);
            }
            return bean;
        }
    }
}
