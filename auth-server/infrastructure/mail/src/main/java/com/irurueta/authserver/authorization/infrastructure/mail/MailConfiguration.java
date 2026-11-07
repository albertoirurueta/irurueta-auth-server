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
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mail.javamail.JavaMailSender;

import org.thymeleaf.TemplateEngine;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Wires the SMTP implementation of {@link AccountMailer}. The message source is private to the mailer, so it never
 * competes with the application's own {@code MessageSource} bean.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(MailProperties.class)
public class MailConfiguration {

    /** Base name of the message bundles of this module. */
    static final String BUNDLE = "mail/account-mail";

    /** Base name of the message bundle of the one-time token e-mails. */
    static final String OTT_BUNDLE = "mail/ott-mail";

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
     * Creates the e-mail one-time token delivery. Its Thymeleaf engine is built here and deliberately not exposed as
     * a bean, because a {@code TemplateEngine} bean would replace the one of the web pages.
     *
     * @param mailSender Spring Mail sender configured by {@code spring.mail.*}.
     * @param properties sender, base URL and locale.
     * @return the e-mail delivery of one-time tokens.
     */
    @Bean
    public OttDelivery emailOttDelivery(final JavaMailSender mailSender, final MailProperties properties) {
        final var messages = ottMessages();
        return new ThymeleafOttMailer(mailSender, ottTemplateEngine(messages), messages, properties);
    }

    /**
     * Builds the message source of the one-time token e-mails.
     *
     * @return a source over {@code mail/ott-mail} that never falls back to the platform's locale.
     */
    static MessageSource ottMessages() {
        final var source = new ResourceBundleMessageSource();
        source.setBasename(OTT_BUNDLE);
        source.setDefaultEncoding(StandardCharsets.UTF_8.name());
        source.setFallbackToSystemLocale(false);
        return source;
    }

    /**
     * Builds the private Thymeleaf engine of the one-time token e-mails: HTML mode for {@code mail/*.html}, text
     * mode for {@code mail/*.txt}, both from the classpath.
     *
     * @param messages source of the texts referenced by the templates.
     * @return the engine.
     */
    static TemplateEngine ottTemplateEngine(final MessageSource messages) {
        final var engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver("mail/*.html", TemplateMode.HTML, 1));
        engine.addTemplateResolver(resolver("mail/*.txt", TemplateMode.TEXT, 2));
        engine.setTemplateEngineMessageSource(messages);
        return engine;
    }

    /**
     * Builds a classpath resolver for the templates matching a pattern.
     *
     * @param pattern resolvable template names.
     * @param mode    template mode.
     * @param order   position among the resolvers.
     * @return the resolver.
     */
    private static ClassLoaderTemplateResolver resolver(final String pattern, final TemplateMode mode,
                                                        final int order) {
        final var resolver = new ClassLoaderTemplateResolver();
        resolver.setResolvablePatterns(Set.of(pattern));
        resolver.setTemplateMode(mode);
        resolver.setCharacterEncoding(StandardCharsets.UTF_8.name());
        resolver.setOrder(order);
        resolver.setCheckExistence(true);
        return resolver;
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
