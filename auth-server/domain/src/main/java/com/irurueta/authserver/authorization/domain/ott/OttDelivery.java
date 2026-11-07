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
package com.irurueta.authserver.authorization.domain.ott;

import java.net.URI;
import java.time.Duration;

/**
 * Port that delivers a one-time token to a destination through a channel.
 */
public interface OttDelivery {

    /**
     * Delivers a numeric code.
     *
     * @param channel     channel to use.
     * @param destination e-mail address or E.164 phone number, according to the channel.
     * @param code        the code in clear text.
     * @param validFor    how long the code stays valid, shown to the user.
     * @throws OttDeliveryException if the code could not be delivered.
     */
    void deliverCode(OttChannel channel, String destination, String code, Duration validFor);

    /**
     * Delivers a magic link.
     *
     * @param channel     channel to use.
     * @param destination e-mail address or E.164 phone number, according to the channel.
     * @param link        the link that opens the confirmation page.
     * @param validFor    how long the link stays valid, shown to the user.
     * @throws OttDeliveryException if the link could not be delivered.
     */
    void deliverLink(OttChannel channel, String destination, URI link, Duration validFor);
}
