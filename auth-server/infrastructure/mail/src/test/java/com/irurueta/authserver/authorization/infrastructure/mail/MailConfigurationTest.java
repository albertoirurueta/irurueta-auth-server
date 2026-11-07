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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * Unit tests of {@link MailConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class MailConfigurationTest {

    /** Mocked sender. */
    @Mock
    private JavaMailSender mailSender;

    /**
     * The bean is the SMTP mailer.
     */
    @Test
    void accountMailer_whenCalled_returnsSmtpMailer() {
        final var mailer = new MailConfiguration().accountMailer(mailSender,
                new MailProperties(null, null, null));

        assertInstanceOf(SmtpAccountMailer.class, mailer);
    }

    /**
     * The one-time token delivery is the Thymeleaf mailer.
     */
    @Test
    void emailOttDelivery_whenCalled_returnsThymeleafMailer() {
        final var delivery = new MailConfiguration().emailOttDelivery(mailSender,
                new MailProperties(null, null, null));

        assertInstanceOf(ThymeleafOttMailer.class, delivery);
    }

    /**
     * The one-time token bundle resolves for an unknown locale without using the platform locale.
     */
    @Test
    void ottMessages_whenLocaleIsUnknown_resolvesBaseBundle() {
        final var subject = MailConfiguration.ottMessages()
                .getMessage("ott.code.subject", null, Locale.JAPANESE);

        assertEquals("Your sign-in code", subject);
    }

    /**
     * The bundle resolves for an unknown locale without using the platform locale.
     */
    @Test
    void mailMessages_whenLocaleIsUnknown_resolvesBaseBundle() {
        final var subject = MailConfiguration.mailMessages()
                .getMessage("mail.reset.subject", null, Locale.JAPANESE);

        assertEquals("Choose a new sign-in secret", subject);
    }
}
