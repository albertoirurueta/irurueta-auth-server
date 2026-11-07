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

import java.time.Duration;
import java.util.Locale;

/**
 * Texts of the SMS messages. SMS bodies are short and machine-oriented, so they are fixed English text.
 */
public final class SmsMessages {

    /** Hidden constructor of a utility class. */
    private SmsMessages() {
    }

    /**
     * Builds the text of a message that carries a one-time code.
     *
     * @param code     the clear-text code.
     * @param validFor how long the code is valid.
     * @return the text.
     */
    public static String verificationCode(final String code, final Duration validFor) {
        return String.format(Locale.ROOT, "Your verification code is %s. It is valid for %d minutes.", code,
                Math.max(1L, validFor.toMinutes()));
    }
}
