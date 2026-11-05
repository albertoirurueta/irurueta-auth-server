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

import java.util.Locale;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings of the e-mails sent by {@link SmtpAccountMailer}. The SMTP connection itself is configured with the
 * standard {@code spring.mail.*} properties and holds no credentials in this repository.
 *
 * @param from sender address of every message.
 * @param baseUrl public base URL of the authorization server, used to build the links of the messages (without a
 *                trailing slash).
 * @param locale language of the messages; it is explicit configuration, never the platform's default.
 */
// tag::mail-properties[]
@ConfigurationProperties(prefix = "authserver.mail")
public record MailProperties(String from, String baseUrl, Locale locale) {

    /** Sender used when none is configured. */
    public static final String DEFAULT_FROM = "no-reply@localhost";

    /** Base URL used when none is configured. */
    public static final String DEFAULT_BASE_URL = "http://localhost:9000";

    /**
     * Applies the defaults of the missing values and removes a trailing slash of the base URL.
     *
     * @param from sender address, or {@code null} for {@link #DEFAULT_FROM}.
     * @param baseUrl public base URL, or {@code null} for {@link #DEFAULT_BASE_URL}.
     * @param locale language of the messages, or {@code null} for English.
     */
    public MailProperties {
        from = from == null || from.isBlank() ? DEFAULT_FROM : from;
        final var url = baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE_URL : baseUrl;
        baseUrl = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        locale = locale == null ? Locale.ENGLISH : locale;
    }
}
// end::mail-properties[]
