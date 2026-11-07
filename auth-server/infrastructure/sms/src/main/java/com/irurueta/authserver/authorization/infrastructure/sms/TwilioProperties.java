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

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Twilio credentials and sender, bound from the environment variables {@code AUTHSERVER_SMS_TWILIO_*} only; no value
 * is ever written in a file of this repository. Used by the {@code twilio} profile.
 *
 * @param accountSid          Twilio account SID.
 * @param authToken           Twilio auth token (secret).
 * @param from                sender phone number in E.164, or blank when a messaging service is used.
 * @param messagingServiceSid SID of the messaging service, or blank when a sender number is used.
 */
@ConfigurationProperties(prefix = "authserver.sms.twilio")
public record TwilioProperties(String accountSid, String authToken, String from, String messagingServiceSid) {

    @Override
    public String toString() {
        return "TwilioProperties[accountSid=" + accountSid + ", authToken=***, from=" + from
                + ", messagingServiceSid=" + messagingServiceSid + "]";
    }
}
