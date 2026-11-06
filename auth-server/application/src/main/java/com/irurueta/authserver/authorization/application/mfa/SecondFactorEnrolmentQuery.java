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
package com.irurueta.authserver.authorization.application.mfa;

import java.util.UUID;

/**
 * Extension point that tells whether a user has confirmed one kind of second factor. Every second factor declares
 * one bean of this type (TOTP does it with its {@code IsTotpEnabledUseCase}); {@link HasConfirmedSecondFactorUseCase}
 * asks all of them, so a user who has confirmed any second factor is always asked for one at sign-in and must step up
 * before removing it, without this package knowing the factors.
 */
public interface SecondFactorEnrolmentQuery {

    /**
     * Tells whether a user has confirmed this second factor.
     *
     * @param userId identifier of the user.
     * @return {@code true} when the user has it and its enrolment is confirmed.
     */
    boolean hasConfirmed(UUID userId);
}
