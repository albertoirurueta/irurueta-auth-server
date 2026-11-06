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

/**
 * Authentication context class references ({@code acr}) that this server reports and understands.
 */
public final class AuthenticationContextClass {

    /** Reference of an authentication with a password only. */
    public static final String PASSWORD = "urn:irurueta:acr:pwd";

    /** Reference of an authentication that satisfied the multi-factor policy. */
    public static final String MULTI_FACTOR = "urn:irurueta:acr:mfa";

    /**
     * Not instantiable: a holder of constants.
     */
    private AuthenticationContextClass() {
    }
}
