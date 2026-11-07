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

package com.irurueta.authserver.authorization.application.ott;

import java.time.Duration;

/**
 * Outcome of a request for a one-time code. It is identical whether or not a code was sent, so that it cannot reveal
 * whether an identifier exists.
 *
 * @param accepted always {@code true}: the request was accepted, nothing is promised about delivery.
 * @param expiresIn how long a code is valid, from the policy.
 */
public record OneTimeCodeRequestResult(boolean accepted, Duration expiresIn) {
}
