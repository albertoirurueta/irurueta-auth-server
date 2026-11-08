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

package com.irurueta.authserver.serviceclient.device;

/**
 * What one poll of the token endpoint answered (RFC 8628 section 3.5).
 */
public sealed interface PollOutcome {

    /**
     * The user approved the request.
     *
     * @param token the issued tokens.
     */
    record Granted(TokenResponse token) implements PollOutcome {
    }

    /**
     * {@code authorization_pending}: the user has not decided yet; poll again after the same interval.
     */
    record Pending() implements PollOutcome {
    }

    /**
     * {@code slow_down}: polling too fast; the interval grows by {@link DeviceFlowCli#SLOW_DOWN_INCREMENT_SECONDS}.
     */
    record SlowDown() implements PollOutcome {
    }

    /**
     * Any other error ({@code access_denied}, {@code expired_token}, ...): the flow is over.
     *
     * @param error       the OAuth error code.
     * @param description the optional human-readable description, or {@code null}.
     */
    record Failed(String error, String description) implements PollOutcome {
    }
}
