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

// tag::social-sign-in-methods-lock[]
/**
 * Port that serializes the removals of the sign-in methods of one account (unlinking an identity, unbinding a
 * certificate), so that two concurrent removals cannot each count the other's method as remaining and together leave
 * the account with no way to sign in.
 */
public interface SignInMethodsLock {

    /**
     * Takes the lock of an account until the caller's transaction ends; a second caller for the same account waits.
     *
     * @param userId identifier of the account.
     */
    void lock(UUID userId);
}
// end::social-sign-in-methods-lock[]
