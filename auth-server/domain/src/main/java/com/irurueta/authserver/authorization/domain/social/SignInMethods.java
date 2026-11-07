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
 * The ways an account can sign in with. A use case that removes one asks for the methods without it
 * ({@link #withoutFederatedIdentity()}, {@link #withoutCertificate()}) and refuses the removal when none is left.
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

    /**
     * Counts the methods without one linked external identity.
     *
     * @return the methods once one identity is removed; the count never goes below zero.
     */
    public SignInMethods withoutFederatedIdentity() {
        return new SignInMethods(password, Math.max(0, federatedIdentities - 1), passkey, certificates);
    }

    /**
     * Counts the methods without one bound client certificate.
     *
     * @return the methods once one certificate is unbound; the count never goes below zero.
     */
    public SignInMethods withoutCertificate() {
        return new SignInMethods(password, federatedIdentities, passkey, Math.max(0, certificates - 1));
    }
}
