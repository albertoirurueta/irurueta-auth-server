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

package com.irurueta.authserver.authorization.application.sms;

/**
 * Thrown when an SMS is not sent because its country is not served, or cannot be determined.
 */
public class SmsCountryNotAllowedException extends SmsRefusedException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     */
    public SmsCountryNotAllowedException() {
        super("SMS messages are not sent to that country");
    }
}
