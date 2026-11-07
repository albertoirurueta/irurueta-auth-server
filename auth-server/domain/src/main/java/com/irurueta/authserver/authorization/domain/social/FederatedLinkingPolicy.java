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

import static com.irurueta.authserver.authorization.domain.Preconditions.isBlank;

import com.irurueta.authserver.authorization.domain.password.UserAccount;

/**
 * Rules of identity brokering: when an external identity may be tied to an account, and when it may be removed. It
 * is pure; the use cases ask it and act on the answer.
 */
public class FederatedLinkingPolicy {

    /**
     * Tells whether an external identity may be linked to the account that has its e-mail address. Both sides must
     * vouch for the address: the provider says it is verified, and the account verified it too. Otherwise somebody
     * could register an account with a victim's address, never verify it, and wait for the victim to sign in with a
     * provider.
     *
     * @param account           account that has the e-mail address.
     * @param providerEmail     e-mail address the provider reported.
     * @param providerVerified  whether the provider says it verified the address.
     * @return {@code true} when the identity may be linked.
     */
    public boolean mayLinkByEmail(
            final UserAccount account, final String providerEmail, final boolean providerVerified) {
        return account != null && providerVerified && !isBlank(providerEmail) && account.emailVerified();
    }

    /**
     * Tells whether a new account may be created from an external identity: the provider must vouch for a usable
     * e-mail address.
     *
     * @param providerEmail    e-mail address the provider reported.
     * @param providerVerified whether the provider says it verified the address.
     * @return {@code true} when the account may be provisioned.
     */
    public boolean mayProvision(final String providerEmail, final boolean providerVerified) {
        return providerVerified && !isBlank(providerEmail);
    }

    /**
     * Tells whether a sign-in with an external provider may reach an account at all: a disabled account is never
     * linked to an identity and never signed in through one, the rule every other sign-in method applies.
     *
     * @param account the account the sign-in resolved to.
     * @return {@code true} when the account may sign in.
     */
    public boolean maySignIn(final UserAccount account) {
        return account != null && account.enabled();
    }

    /**
     * Tells whether a sign-in method (a linked identity, a bound certificate) may be removed: the account must keep at
     * least one other way to sign in.
     *
     * @param remaining ways to sign in left once the method is removed.
     * @return {@code true} when removing it is allowed.
     */
    public boolean mayUnlink(final SignInMethods remaining) {
        return remaining != null && remaining.any();
    }
}
