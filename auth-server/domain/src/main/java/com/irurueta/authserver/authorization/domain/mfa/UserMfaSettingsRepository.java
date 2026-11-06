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
package com.irurueta.authserver.authorization.domain.mfa;

import java.util.UUID;

/**
 * Port that stores the multi-factor settings of a user account.
 */
public interface UserMfaSettingsRepository {

    /**
     * Tells whether an account requires a second factor.
     *
     * @param userId identifier of the user.
     * @return {@code true} when the account requires it; {@code false} when it does not or does not exist.
     */
    boolean isRequired(UUID userId);

    /**
     * Sets whether an account requires a second factor.
     *
     * @param userId   identifier of the user.
     * @param required whether it is required.
     */
    void setRequired(UUID userId, boolean required);
}
