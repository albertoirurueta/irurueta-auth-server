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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link FederatedLinkingPolicy}.
 */
class FederatedLinkingPolicyTest {

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Policy under test. */
    private final FederatedLinkingPolicy policy = new FederatedLinkingPolicy();

    /**
     * Verifies that an identity may be linked when the provider and the account both verified the address.
     */
    @Test
    void mayLinkByEmail_whenBothSidesVerified_returnsTrue() {
        assertTrue(policy.mayLinkByEmail(account(true), EMAIL, true));
    }

    /**
     * Verifies that an address the provider did not verify never links.
     */
    @Test
    void mayLinkByEmail_whenProviderDidNotVerify_returnsFalse() {
        assertFalse(policy.mayLinkByEmail(account(true), EMAIL, false));
    }

    /**
     * Verifies that an account that never verified its address is never linked.
     */
    @Test
    void mayLinkByEmail_whenAccountDidNotVerify_returnsFalse() {
        assertFalse(policy.mayLinkByEmail(account(false), EMAIL, true));
    }

    /**
     * Verifies that a missing address, a blank address or a missing account never link.
     */
    @Test
    void mayLinkByEmail_whenAddressOrAccountIsMissing_returnsFalse() {
        assertFalse(policy.mayLinkByEmail(account(true), null, true));
        assertFalse(policy.mayLinkByEmail(account(true), " ", true));
        assertFalse(policy.mayLinkByEmail(null, EMAIL, true));
    }

    /**
     * Verifies that provisioning needs a verified, non blank address.
     */
    @Test
    void mayProvision_whenAddressIsVerifiedAndPresent_returnsTrue() {
        assertTrue(policy.mayProvision(EMAIL, true));
        assertFalse(policy.mayProvision(EMAIL, false));
        assertFalse(policy.mayProvision(null, true));
        assertFalse(policy.mayProvision("", true));
    }

    /**
     * Verifies that unlinking is allowed only while some way to sign in remains.
     */
    @Test
    void mayUnlink_whenAWayToSignInRemains_returnsTrue() {
        assertTrue(policy.mayUnlink(new SignInMethods(true, 0, false, 0)));
        assertTrue(policy.mayUnlink(new SignInMethods(false, 1, false, 0)));
        assertTrue(policy.mayUnlink(new SignInMethods(false, 0, true, 0)));
        assertTrue(policy.mayUnlink(new SignInMethods(false, 0, false, 1)));
        assertFalse(policy.mayUnlink(new SignInMethods(false, 0, false, 0)));
        assertFalse(policy.mayUnlink(null));
    }

    /**
     * Verifies that only an enabled account may be reached by a federated sign-in.
     */
    @Test
    void maySignIn_whenTheAccountIsEnabled_returnsTrue() {
        final var enabled = account(true);
        final var disabled = new UserAccount(enabled.id(), enabled.username(), enabled.encodedPassword(), false,
                enabled.authorities(), enabled.email(), enabled.emailVerified(), enabled.tenant());

        assertTrue(policy.maySignIn(enabled));
        assertFalse(policy.maySignIn(disabled));
        assertFalse(policy.maySignIn(null));
    }

    /**
     * Builds an account.
     *
     * @param emailVerified whether the account verified its address.
     * @return the account.
     */
    private static UserAccount account(final boolean emailVerified) {
        return new UserAccount(UUID.randomUUID(), "alice", "{noop}x", true, List.of(), EMAIL, emailVerified,
                UserAccount.DEFAULT_TENANT);
    }
}
