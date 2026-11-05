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

package com.irurueta.authserver.authorization.domain.keys;

import java.time.Duration;

/**
 * Port that tells how long the tokens signed with the signing keys stay valid, so that a retired key stays published
 * for as long as any token it signed can still be presented.
 */
@FunctionalInterface
public interface SignedTokenLifetimes {

    /**
     * Finds the longest lifetime of a signed token (an access or ID token) that any registered client can obtain.
     *
     * @return the longest lifetime; never {@code null} and never negative.
     */
    Duration longest();
}
