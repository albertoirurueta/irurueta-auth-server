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

import java.util.List;
import java.util.function.Supplier;

/**
 * Port that stores signing keys.
 */
public interface SigningKeyRepository {

    /**
     * Finds every stored key.
     *
     * @return the keys, in no particular order; empty when there are none.
     */
    List<SigningKey> findAll();

    /**
     * Inserts a key, or replaces the stored key that has the same identifier.
     *
     * @param key the key to store.
     */
    void save(SigningKey key);

    /**
     * Deletes a key.
     *
     * @param kid identifier of the key.
     */
    void deleteByKid(String kid);

    /**
     * Runs an action while holding the cluster-wide rotation lock and inside one transaction, so that two instances
     * can never rotate the keys at the same time. The action's changes are committed together, or not at all.
     *
     * @param action the action to run.
     * @param <T>    type of the result.
     * @return what the action returns.
     */
    <T> T withRotationLock(Supplier<T> action);
}
