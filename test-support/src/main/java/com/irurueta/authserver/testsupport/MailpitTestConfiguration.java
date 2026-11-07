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
package com.irurueta.authserver.testsupport;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.containers.GenericContainer;

/**
 * Starts a Mailpit container for a Spring test context and points the application's mail sender at it, so the
 * messages the application sends can be read back through {@link MailpitClient}. Import it next to
 * {@link PostgresTestConfiguration}.
 */
@TestConfiguration(proxyBeanMethods = false)
public class MailpitTestConfiguration {

    /**
     * Creates the Mailpit container.
     *
     * @return the container, started and stopped by the Spring context lifecycle.
     */
    @Bean
    public GenericContainer<?> mailpitContainer() {
        return Mailpit.newContainer();
    }

    /**
     * Points {@code spring.mail.host} and {@code spring.mail.port} at the container's SMTP server.
     *
     * @param mailpitContainer the container.
     * @return the registrar of the two properties.
     */
    @Bean
    public DynamicPropertyRegistrar mailpitProperties(final GenericContainer<?> mailpitContainer) {
        return registry -> {
            registry.add("spring.mail.host", mailpitContainer::getHost);
            registry.add("spring.mail.port", () -> mailpitContainer.getMappedPort(Mailpit.SMTP_PORT));
        };
    }

    /**
     * Creates the client of the container's HTTP API.
     *
     * @param mailpitContainer the container.
     * @return the client.
     */
    @Bean
    public MailpitClient mailpitClient(final GenericContainer<?> mailpitContainer) {
        return Mailpit.clientOf(mailpitContainer);
    }
}
