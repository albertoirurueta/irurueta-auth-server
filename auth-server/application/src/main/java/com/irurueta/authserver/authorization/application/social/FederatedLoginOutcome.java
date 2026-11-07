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
package com.irurueta.authserver.authorization.application.social;

/**
 * How a sign-in with an external provider found its account.
 */
public enum FederatedLoginOutcome {

    /** The identity was already linked to the account. */
    EXISTING,

    /** The identity was linked to an existing account that has the same verified e-mail address. */
    LINKED,

    /** A new account was created from the identity. */
    PROVISIONED
}
