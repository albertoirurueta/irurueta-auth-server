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

package com.irurueta.authserver.bff.domain.user;

/**
 * The user signed in to the BFF session.
 *
 * @param subject identifier of the user, as issued by the authorization server (the OpenID Connect {@code sub}
 *                claim).
 */
public record SessionUser(String subject) {

    /**
     * Validates the user.
     *
     * @throws IllegalArgumentException if the subject is null or blank.
     */
    public SessionUser {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
    }
}
