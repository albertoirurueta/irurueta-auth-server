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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import jakarta.mail.BodyPart;
import jakarta.mail.Message;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * Unit tests of {@link ThymeleafOttMailer} with a mocked {@link JavaMailSender}, the module's real templates and a
 * real {@link MimeMessage}.
 */
@ExtendWith(MockitoExtension.class)
class ThymeleafOttMailerTest {

    /** Recipient used by the tests. */
    private static final String RECIPIENT = "person@example.com";

    /** Sender used by the tests. */
    private static final String SENDER = "auth@example.com";

    /** A code used by the tests. */
    private static final String CODE = "483920";

    /** A link used by the tests. */
    private static final String LINK = "https://auth.example.com/login/ott/confirm?token=abc123";

    /** Validity used by the tests, in minutes. */
    private static final long MINUTES = 10L;

    /** Language that only the test bundle defines. */
    private static final Locale TEST_LOCALE = Locale.of("tt");

    /** Mocked sender. */
    @Mock
    private JavaMailSender mailSender;

    /** Subject under test. */
    private ThymeleafOttMailer mailer;

    /**
     * Builds the mailer with an English configuration.
     */
    @BeforeEach
    void setUp() {
        mailer = mailer(Locale.ENGLISH);
    }

    /**
     * The code message carries code and validity in both parts.
     *
     * @throws Exception if the message cannot be read.
     */
    @Test
    void deliverCode_whenEmail_sendsMultipartWithCodeAndValidity() throws Exception {
        final var message = prepareMessage();

        mailer.deliverCode(OttChannel.EMAIL, RECIPIENT, CODE, Duration.ofMinutes(MINUTES));

        final var sent = sent();
        assertEquals(RECIPIENT, ((InternetAddress) sent.getRecipients(Message.RecipientType.TO)[0]).getAddress());
        assertEquals(SENDER, ((InternetAddress) sent.getFrom()[0]).getAddress());
        assertEquals("Your sign-in code", sent.getSubject());
        final var text = partContent(message, "text/plain");
        final var html = partContent(message, "text/html");
        assertTrue(text.contains(CODE));
        assertTrue(text.contains("10 minute(s)"));
        assertTrue(html.contains(CODE));
        assertTrue(html.contains("10 minute(s)"));
        assertTrue(html.contains("<html"));
    }

    /**
     * The link message carries the link unescaped in the text and as an anchor in the HTML.
     *
     * @throws Exception if the message cannot be read.
     */
    @Test
    void deliverLink_whenEmail_sendsMultipartWithLinkAndValidity() throws Exception {
        final var message = prepareMessage();

        mailer.deliverLink(OttChannel.EMAIL, RECIPIENT, URI.create(LINK), Duration.ofMinutes(MINUTES));

        assertEquals("Your sign-in link", sent().getSubject());
        final var text = partContent(message, "text/plain");
        final var html = partContent(message, "text/html");
        assertTrue(text.contains(LINK));
        assertTrue(text.contains("10 minute(s)"));
        assertTrue(html.contains("href=\"" + LINK + "\""));
        assertTrue(html.contains("10 minute(s)"));
    }

    /**
     * A validity below one minute is shown as one minute.
     *
     * @throws Exception if the message cannot be read.
     */
    @Test
    void deliverCode_whenValidityIsShorterThanAMinute_showsOneMinute() throws Exception {
        final var message = prepareMessage();

        mailer.deliverCode(OttChannel.EMAIL, RECIPIENT, CODE, Duration.ofSeconds(1L));

        assertTrue(partContent(message, "text/plain").contains("1 minute(s)"));
    }

    /**
     * The language comes from the mail properties.
     *
     * @throws Exception if the message cannot be read.
     */
    @Test
    void deliverCode_whenLocaleIsConfigured_usesItForSubject() throws Exception {
        prepareMessage();
        mailer = mailer(TEST_LOCALE);

        mailer.deliverCode(OttChannel.EMAIL, RECIPIENT, CODE, Duration.ofMinutes(MINUTES));

        assertEquals("Test locale code subject", sent().getSubject());
    }

    /**
     * Another channel is refused and nothing is sent.
     */
    @Test
    void deliverCode_whenChannelIsSms_throwsIllegalArgumentException() {
        final var duration = Duration.ofMinutes(MINUTES);

        assertThrows(IllegalArgumentException.class,
                () -> mailer.deliverCode(OttChannel.SMS, RECIPIENT, CODE, duration));

        verify(mailSender, never()).send(any(MimeMessage.class));
    }

    /**
     * Another channel is refused for links too.
     */
    @Test
    void deliverLink_whenChannelIsSms_throwsIllegalArgumentException() {
        final var link = URI.create(LINK);
        final var duration = Duration.ofMinutes(MINUTES);

        assertThrows(IllegalArgumentException.class,
                () -> mailer.deliverLink(OttChannel.SMS, RECIPIENT, link, duration));

        verify(mailSender, never()).send(any(MimeMessage.class));
    }

    /**
     * A transport failure becomes a delivery failure that leaks neither the address nor the code.
     */
    @Test
    void deliverCode_whenSendFails_throwsSanitizedOttDeliveryException() {
        prepareMessage();
        doThrow(new MailSendException("failed for " + RECIPIENT + " code " + CODE))
                .when(mailSender).send(any(MimeMessage.class));
        final var duration = Duration.ofMinutes(MINUTES);

        final var error = assertThrows(OttDeliveryException.class,
                () -> mailer.deliverCode(OttChannel.EMAIL, RECIPIENT, CODE, duration));

        assertSanitized(error, CODE);
    }

    /**
     * A failure while delivering a link leaks neither the address nor the link.
     */
    @Test
    void deliverLink_whenSendFails_throwsSanitizedOttDeliveryException() {
        prepareMessage();
        doThrow(new MailSendException("failed for " + RECIPIENT + " " + LINK))
                .when(mailSender).send(any(MimeMessage.class));
        final var link = URI.create(LINK);
        final var duration = Duration.ofMinutes(MINUTES);

        final var error = assertThrows(OttDeliveryException.class,
                () -> mailer.deliverLink(OttChannel.EMAIL, RECIPIENT, link, duration));

        assertSanitized(error, LINK);
    }

    /**
     * An invalid address is a delivery failure, not a raw messaging exception.
     */
    @Test
    void deliverCode_whenAddressIsInvalid_throwsOttDeliveryException() {
        prepareMessage();
        final var duration = Duration.ofMinutes(MINUTES);

        final var error = assertThrows(OttDeliveryException.class,
                () -> mailer.deliverCode(OttChannel.EMAIL, "not an address <", CODE, duration));

        assertSanitized(error, CODE);
        verify(mailSender, never()).send(any(MimeMessage.class));
    }

    /**
     * Builds a mailer for a locale.
     *
     * @param locale language of the messages.
     * @return the mailer over the module's real templates and bundle.
     */
    private ThymeleafOttMailer mailer(final Locale locale) {
        final var messages = MailConfiguration.ottMessages();
        return new ThymeleafOttMailer(mailSender, MailConfiguration.ottTemplateEngine(messages), messages,
                new MailProperties(SENDER, "https://auth.example.com", locale));
    }

    /**
     * Makes the mocked sender hand out a real message.
     *
     * @return that message.
     */
    private MimeMessage prepareMessage() {
        final var message = new MimeMessage(Session.getInstance(new Properties()));
        when(mailSender.createMimeMessage()).thenReturn(message);
        return message;
    }

    /**
     * Captures the message handed to the sender.
     *
     * @return the sent message.
     */
    private MimeMessage sent() {
        final var captor = ArgumentCaptor.<MimeMessage>captor();
        verify(mailSender).send(captor.capture());
        return captor.getValue();
    }

    /**
     * Checks that a failure carries only generic text anywhere in its cause chain.
     *
     * @param error  the failure.
     * @param secret the code or link that must not appear.
     */
    private static void assertSanitized(final OttDeliveryException error, final String secret) {
        Throwable current = error;
        while (current != null) {
            final var text = String.valueOf(current.getMessage());
            assertFalse(text.contains(RECIPIENT));
            assertFalse(text.contains("example.com"));
            assertFalse(text.contains(secret));
            current = current.getCause();
        }
        assertEquals(ThymeleafOttMailer.FAILURE_MESSAGE, error.getMessage());
        assertInstanceOf(IllegalStateException.class, error.getCause());
        assertNull(error.getCause().getCause());
    }

    /**
     * Finds the content of the first part of a MIME type, searching nested multiparts.
     *
     * @param part     part to search.
     * @param mimeType wanted type.
     * @return the content, or an empty text when there is none.
     * @throws Exception if the message cannot be read.
     */
    private static String partContent(final MimeMessage part, final String mimeType) throws Exception {
        part.saveChanges();
        return partContent((Part) part, mimeType);
    }

    /**
     * Finds the content of the first part of a MIME type, searching nested multiparts.
     *
     * @param part     part to search.
     * @param mimeType wanted type.
     * @return the content, or an empty text when there is none.
     * @throws Exception if the message cannot be read.
     */
    private static String partContent(final Part part, final String mimeType) throws Exception {
        if (part.isMimeType(mimeType)) {
            return (String) part.getContent();
        }
        if (part.isMimeType("multipart/*")) {
            final var multipart = (Multipart) part.getContent();
            for (var i = 0; i < multipart.getCount(); i++) {
                final BodyPart child = multipart.getBodyPart(i);
                final var content = partContent(child, mimeType);
                if (!content.isEmpty()) {
                    return content;
                }
            }
        }
        return "";
    }
}
