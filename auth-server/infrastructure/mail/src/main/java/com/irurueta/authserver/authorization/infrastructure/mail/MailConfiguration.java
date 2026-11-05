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

package com.irurueta.authserver.authorization.infrastructure.mail;

import com.irurueta.authserver.authorization.domain.account.AccountMailer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mail.javamail.JavaMailSender;

import java.nio.charset.StandardCharsets;

/**
 * Wires the SMTP implementation of {@link AccountMailer}. The message source is private to the mailer, so it never
 * competes with the application's own {@code MessageSource} bean.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(MailProperties.class)
public class MailConfiguration {

    /** Base name of the message bundles of this module. */
    static final String BUNDLE = "mail/account-mail";

    /**
     * Creates the mailer.
     *
     * @param mailSender Spring Mail sender configured by {@code spring.mail.*}.
     * @param properties sender, base URL and locale.
     * @return the account mailer.
     */
    @Bean
    public AccountMailer accountMailer(final JavaMailSender mailSender, final MailProperties properties) {
        return new SmtpAccountMailer(mailSender, mailMessages(), properties);
    }

    /**
     * Builds the message source of the mailer.
     *
     * @return a source over the module's bundles that never falls back to the platform's locale.
     */
    static MessageSource mailMessages() {
        final var source = new ResourceBundleMessageSource();
        source.setBasename(BUNDLE);
        source.setDefaultEncoding(StandardCharsets.UTF_8.name());
        source.setFallbackToSystemLocale(false);
        return source;
    }
}
