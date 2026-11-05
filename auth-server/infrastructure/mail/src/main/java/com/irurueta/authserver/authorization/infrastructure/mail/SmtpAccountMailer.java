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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * {@link AccountMailer} that sends plain-text messages through SMTP. Subject and body come from a
 * {@link MessageSource} resolved with the explicitly configured locale, never the platform's default. A delivery
 * failure is logged without the address or the token and never propagates, so the caller's answer cannot reveal
 * whether an address is registered.
 */
@Slf4j
@RequiredArgsConstructor
public class SmtpAccountMailer implements AccountMailer {

    /** Message key prefix of the e-mail verification message. */
    static final String VERIFICATION = "mail.verification";

    /** Message key prefix of the already-registered message. */
    static final String ALREADY_REGISTERED = "mail.already-registered";

    /** Message key prefix of the reset message. */
    static final String RESET = "mail.reset";

    /** Message key prefix of the no-account-found message. */
    static final String NO_ACCOUNT = "mail.no-account";

    /** Path of the verification endpoint. */
    static final String VERIFY_PATH = "/api/account/verify?token=";

    /** Path of the page that lets the user choose a new secret. */
    static final String RESET_PATH = "/account/reset?token=";

    /** Sends the messages. */
    private final JavaMailSender mailSender;

    /** Source of the subjects and bodies. */
    private final MessageSource messageSource;

    /** Sender, base URL and locale. */
    private final MailProperties properties;

    @Override
    public void sendEmailVerification(final String email, final String token) {
        send(email, VERIFICATION, properties.baseUrl() + VERIFY_PATH + encode(token));
    }

    @Override
    public void sendAlreadyRegistered(final String email) {
        send(email, ALREADY_REGISTERED, properties.baseUrl());
    }

    @Override
    public void sendPasswordReset(final String email, final String token) {
        send(email, RESET, properties.baseUrl() + RESET_PATH + encode(token));
    }

    @Override
    public void sendNoAccountFound(final String email) {
        send(email, NO_ACCOUNT, properties.baseUrl());
    }

    /**
     * Builds and sends one message, swallowing delivery failures.
     *
     * @param email recipient address.
     * @param prefix message key prefix; {@code .subject} and {@code .body} are appended.
     * @param link link inserted as the first argument of the body.
     */
    private void send(final String email, final String prefix, final String link) {
        final var locale = properties.locale();
        final var message = new SimpleMailMessage();
        message.setFrom(properties.from());
        message.setTo(email);
        message.setSubject(messageSource.getMessage(prefix + ".subject", null, locale));
        message.setText(messageSource.getMessage(prefix + ".body", new Object[]{link}, locale));
        try {
            mailSender.send(message);
        } catch (final MailException e) {
            log.warn("Could not deliver the {} message: {}", prefix, e.getClass().getSimpleName());
        }
    }

    /**
     * Encodes a value for a query parameter.
     *
     * @param value value to encode.
     * @return the encoded value.
     */
    private static String encode(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
