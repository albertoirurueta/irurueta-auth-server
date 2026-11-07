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

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import jakarta.mail.MessagingException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.exceptions.TemplateEngineException;

/**
 * {@link OttDelivery} that e-mails one-time codes and magic links as multipart messages (plain text and HTML)
 * rendered with Thymeleaf. Only {@link OttChannel#EMAIL} is handled: asking it to deliver through another channel is
 * a programming error and is refused with an {@link IllegalArgumentException}, so a token is never silently dropped.
 * Subject and texts come from a {@link MessageSource} resolved with the explicitly configured locale, never the
 * platform's default. A delivery failure becomes an {@link OttDeliveryException} with a generic message and a
 * sanitized cause: neither the address, nor the code, nor the link is ever logged or carried by an exception.
 */
// tag::ott-mailer[]
@Slf4j
@RequiredArgsConstructor
public class ThymeleafOttMailer implements OttDelivery {

    /** Template of the code message (without extension). */
    static final String CODE_TEMPLATE = "mail/ott-code";

    /** Template of the link message (without extension). */
    static final String LINK_TEMPLATE = "mail/ott-link";

    /** Extension of the HTML templates. */
    static final String HTML_EXTENSION = ".html";

    /** Extension of the plain-text templates. */
    static final String TEXT_EXTENSION = ".txt";

    /** Message key of the subject of the code message. */
    static final String CODE_SUBJECT = "ott.code.subject";

    /** Message key of the subject of the link message. */
    static final String LINK_SUBJECT = "ott.link.subject";

    /** Template variable holding the code. */
    static final String CODE_VARIABLE = "code";

    /** Template variable holding the link. */
    static final String LINK_VARIABLE = "link";

    /** Template variable holding the validity in minutes. */
    static final String VALID_MINUTES_VARIABLE = "validMinutes";

    /** Generic message of every delivery failure. */
    static final String FAILURE_MESSAGE = "Could not deliver the one-time token by e-mail";

    /** Seconds in a minute. */
    private static final long SECONDS_PER_MINUTE = 60L;

    /** Sends the messages. */
    private final JavaMailSender mailSender;

    /** Renders the templates; private to this mailer. */
    private final TemplateEngine templateEngine;

    /** Source of the subjects. */
    private final MessageSource messageSource;

    /** Sender, base URL and locale. */
    private final MailProperties properties;

    @Override
    public void deliverCode(final OttChannel channel, final String destination, final String code,
                            final Duration validFor) {
        requireEmail(channel);
        send(destination, CODE_SUBJECT, CODE_TEMPLATE, CODE_VARIABLE, code, validFor);
    }

    @Override
    public void deliverLink(final OttChannel channel, final String destination, final URI link,
                            final Duration validFor) {
        requireEmail(channel);
        send(destination, LINK_SUBJECT, LINK_TEMPLATE, LINK_VARIABLE, link.toString(), validFor);
    }

    /**
     * Renders and sends one message.
     *
     * @param destination recipient address.
     * @param subjectKey  message key of the subject.
     * @param template    template name without extension.
     * @param variable    name of the variable that holds the secret value.
     * @param value       the code or link.
     * @param validFor    validity shown to the user.
     * @throws OttDeliveryException if the message cannot be rendered or delivered.
     */
    private void send(final String destination, final String subjectKey, final String template,
                      final String variable, final String value, final Duration validFor) {
        final var locale = properties.locale();
        final var context = new Context(locale);
        context.setVariable(variable, value);
        context.setVariable(VALID_MINUTES_VARIABLE, minutes(validFor));
        try {
            final var text = templateEngine.process(template + TEXT_EXTENSION, context);
            final var html = templateEngine.process(template + HTML_EXTENSION, context);
            final var message = mailSender.createMimeMessage();
            final var helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setFrom(properties.from());
            helper.setTo(destination);
            helper.setSubject(messageSource.getMessage(subjectKey, null, locale));
            helper.setText(text, html);
            mailSender.send(message);
        } catch (final MailException | MessagingException | TemplateEngineException e) {
            // Only the type of the failure is kept: its message may contain the address or the rendered body.
            log.warn("Could not deliver a one-time token by e-mail ({})", e.getClass().getSimpleName());
            throw new OttDeliveryException(FAILURE_MESSAGE,
                    new IllegalStateException("Delivery failed with " + e.getClass().getName()));
        }
    }

    /**
     * Rounds a duration up to whole minutes, at least one.
     *
     * @param validFor the validity.
     * @return the minutes to show.
     */
    private static long minutes(final Duration validFor) {
        final var seconds = validFor.toSeconds();
        return Math.max(1L, (seconds + SECONDS_PER_MINUTE - 1L) / SECONDS_PER_MINUTE);
    }

    /**
     * Refuses a channel other than e-mail.
     *
     * @param channel requested channel.
     * @throws IllegalArgumentException if the channel is not {@link OttChannel#EMAIL}.
     */
    private static void requireEmail(final OttChannel channel) {
        if (channel != OttChannel.EMAIL) {
            throw new IllegalArgumentException("Unsupported channel for the e-mail delivery: " + channel);
        }
    }
}
// end::ott-mailer[]
