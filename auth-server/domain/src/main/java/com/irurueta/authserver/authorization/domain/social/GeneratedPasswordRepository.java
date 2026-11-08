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
package com.irurueta.authserver.authorization.domain.social;

import java.util.UUID;

/**
 * Port that remembers which accounts only hold a password the server generated and nobody knows: the accounts
 * created by the first sign-in with an external provider. Every account row carries a password hash, so without this
 * mark a provisioned account would count as having a password sign-in method. Setting a password (registration, reset
 * or change) clears the mark. It never returns {@code null}.
 */
public interface GeneratedPasswordRepository {

    /**
     * Marks the password of an account as generated, that is, unknown to its owner.
     *
     * @param userId identifier of the account.
     */
    void markGenerated(UUID userId);

    /**
     * Tells whether the password of an account is a generated one.
     *
     * @param userId identifier of the account.
     * @return {@code true} when the account has no password its owner knows.
     */
    boolean isGenerated(UUID userId);
}
