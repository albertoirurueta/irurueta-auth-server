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
package com.irurueta.authserver.authorization.domain.sms;

import java.time.Duration;

/**
 * A spending cap of text messages: what may be spent in a window that ends at the message being sent.
 *
 * @param window    length of the window; positive.
 * @param capMicros what may be spent in the window, the message being sent included, in millionths of the budget
 *                  currency; not negative.
 */
public record SmsSpendCap(Duration window, long capMicros) {

    /**
     * Validates the cap.
     *
     * @throws IllegalArgumentException if the window is missing or not positive, or the cap is negative.
     */
    public SmsSpendCap {
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        if (capMicros < 0) {
            throw new IllegalArgumentException("capMicros must not be negative");
        }
    }
}
