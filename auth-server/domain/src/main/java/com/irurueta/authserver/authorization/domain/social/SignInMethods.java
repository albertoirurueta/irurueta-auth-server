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

/**
 * The ways an account can still sign in with, counted without the one being removed.
 *
 * @param password                whether the account has a password its owner knows.
 * @param federatedIdentities     number of linked external identities.
 * @param passkey                 whether the account has a registered passkey.
 * @param certificates            number of bound client certificates.
 */
public record SignInMethods(boolean password, long federatedIdentities, boolean passkey, long certificates) {

    /**
     * Tells whether any way to sign in is left.
     *
     * @return {@code true} when there is a password, an identity, a passkey or a certificate.
     */
    public boolean any() {
        return password || federatedIdentities > 0 || passkey || certificates > 0;
    }
}
