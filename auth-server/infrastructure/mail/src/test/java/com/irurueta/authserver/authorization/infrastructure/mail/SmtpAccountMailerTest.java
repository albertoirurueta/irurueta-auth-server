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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * Unit tests of {@link SmtpAccountMailer} with a mocked {@link JavaMailSender} and the module's real bundle.
 */
@ExtendWith(MockitoExtension.class)
class SmtpAccountMailerTest {

    /** Recipient used by the tests. */
    private static final String RECIPIENT = "user@example.com";

    /** Sender used by the tests. */
    private static final String SENDER = "auth@example.com";

    /** Base URL used by the tests. */
    private static final String BASE_URL = "https://auth.example.com";

    /** Mocked sender. */
    @Mock
    private JavaMailSender mailSender;

    /** Subject under test. */
    private SmtpAccountMailer mailer;

    /**
     * Pins the thread locale and builds the mailer with an English configuration.
     */
    @BeforeEach
    void setUp() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        mailer = new SmtpAccountMailer(mailSender, MailConfiguration.mailMessages(),
                new MailProperties(SENDER, BASE_URL, Locale.ENGLISH));
    }

    /**
     * The verification message links to the verification endpoint with the encoded value.
     */
    @Test
    void sendEmailVerification_whenCalled_sendsMessageWithEncodedLink() {
        final var suffix = Long.toHexString(System.nanoTime());
        final var value = "a b+" + suffix;

        mailer.sendEmailVerification(RECIPIENT, value);

        final var message = captureMessage();
        assertEquals(SENDER, message.getFrom());
        assertEquals(RECIPIENT, message.getTo()[0]);
        assertEquals("Confirm your e-mail address", message.getSubject());
        final var text = message.getText();
        assertNotNull(text);
        assertTrue(text.contains(BASE_URL + SmtpAccountMailer.VERIFY_PATH + "a+b%2B" + suffix));
        assertFalse(text.contains("a b"));
    }

    /**
     * The already-registered message carries the base URL.
     */
    @Test
    void sendAlreadyRegistered_whenCalled_sendsMessageWithBaseUrl() {
        mailer.sendAlreadyRegistered(RECIPIENT);

        final var message = captureMessage();
        assertEquals("Your e-mail address is already registered", message.getSubject());
        assertNotNull(message.getText());
        assertTrue(message.getText().contains(BASE_URL));
    }

    /**
     * The reset message links to the reset page with the value.
     */
    @Test
    void sendPasswordReset_whenCalled_sendsMessageWithResetLink() {
        final var value = Long.toHexString(System.nanoTime());

        mailer.sendPasswordReset(RECIPIENT, value);

        final var message = captureMessage();
        assertEquals(RECIPIENT, message.getTo()[0]);
        assertEquals("Choose a new sign-in secret", message.getSubject());
        assertNotNull(message.getText());
        assertTrue(message.getText().contains(BASE_URL + SmtpAccountMailer.RESET_PATH + value));
    }

    /**
     * The no-account message does not contain any link material besides the base URL.
     */
    @Test
    void sendNoAccountFound_whenCalled_sendsMessageWithBaseUrl() {
        mailer.sendNoAccountFound(RECIPIENT);

        final var message = captureMessage();
        assertEquals("Reset requested for this e-mail address", message.getSubject());
        assertNotNull(message.getText());
        assertTrue(message.getText().contains(BASE_URL));
    }

    /**
     * The configured locale is used, not the thread or platform locale.
     */
    @Test
    void sendNoAccountFound_whenLocaleIsConfigured_usesConfiguredLocaleNotThreadLocale() {
        LocaleContextHolder.setLocale(Locale.GERMAN);
        final var other = new SmtpAccountMailer(mailSender, MailConfiguration.mailMessages(),
                new MailProperties(SENDER, BASE_URL, Locale.ENGLISH));

        other.sendNoAccountFound(RECIPIENT);

        assertEquals("Reset requested for this e-mail address", captureMessage().getSubject());
    }

    /**
     * A delivery failure is swallowed.
     */
    @Test
    void sendEmailVerification_whenDeliveryFails_doesNotPropagate() {
        doThrow(new MailSendException("down")).when(mailSender).send(any(SimpleMailMessage.class));

        assertDoesNotThrow(() -> mailer.sendEmailVerification(RECIPIENT, "x"));
    }

    /**
     * Captures the single message handed to the sender.
     *
     * @return the captured message.
     */
    private SimpleMailMessage captureMessage() {
        final var captor = ArgumentCaptor.<SimpleMailMessage>captor();
        verify(mailSender).send(captor.capture());
        return captor.getValue();
    }
}
