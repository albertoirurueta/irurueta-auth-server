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

package com.irurueta.authserver.authorization.infrastructure.sms;

import com.twilio.http.TwilioRestClient;
import com.twilio.rest.api.v2010.account.Message;
import org.springframework.util.StringUtils;

/**
 * Thin wrapper over the Twilio SDK, so the sender can be unit-tested with a mock.
 */
public final class TwilioMessageClient {

    /** Client holding the credentials. */
    private final TwilioRestClient restClient;

    /** Sender number, or {@code null} when a messaging service is used. */
    private final String from;

    /** Messaging service SID, or {@code null} when a sender number is used. */
    private final String messagingServiceSid;

    /**
     * Creates the client.
     *
     * @param properties credentials and sender.
     * @throws IllegalStateException if the credentials or the sender are not configured.
     */
    public TwilioMessageClient(final TwilioProperties properties) {
        if (!StringUtils.hasText(properties.accountSid()) || !StringUtils.hasText(properties.authToken())) {
            throw new IllegalStateException(
                    "authserver.sms.twilio.account-sid and auth-token are required by the twilio profile");
        }
        if (!StringUtils.hasText(properties.from()) && !StringUtils.hasText(properties.messagingServiceSid())) {
            throw new IllegalStateException(
                    "authserver.sms.twilio.from or messaging-service-sid is required by the twilio profile");
        }
        this.restClient = new TwilioRestClient.Builder(properties.accountSid(), properties.authToken()).build();
        this.from = StringUtils.hasText(properties.from()) ? properties.from() : null;
        this.messagingServiceSid = properties.messagingServiceSid();
    }

    /**
     * Sends a message.
     *
     * @param to   recipient in E.164.
     * @param text text of the message.
     */
    public void send(final String to, final String text) {
        final var recipient = new com.twilio.type.PhoneNumber(to);
        if (from != null) {
            Message.creator(recipient, new com.twilio.type.PhoneNumber(from), text).create(restClient);
        } else {
            Message.creator(recipient, messagingServiceSid, text).create(restClient);
        }
    }
}
