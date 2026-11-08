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

import java.util.Collection;
import java.util.Objects;

/**
 * How far a provider's own multi-factor authentication is trusted. By default a federated sign-in is a primary factor
 * and the normal second-factor flow applies; only a provider marked as trusted, whose upstream {@code amr} claim
 * proves {@code mfa}, is accepted as a strong sign-in on its own.
 *
 * @param provider provider the setting belongs to.
 * @param trustMfa whether the provider's multi-factor claim is trusted.
 */
public record ProviderTrust(IdentityProvider provider, boolean trustMfa) {

    /** The {@code amr} value (RFC 8176) that says the provider authenticated the user with several factors. */
    public static final String MFA_AMR = "mfa";

    /**
     * Validates the trust setting.
     *
     * @throws IllegalArgumentException if the provider is missing.
     */
    public ProviderTrust {
        if (provider == null) {
            throw new IllegalArgumentException("provider must not be null");
        }
    }

    /**
     * Tells whether a sign-in counts as strong, that is, whether it proves identity without a second factor.
     *
     * @param upstreamAmr {@code amr} values the provider reported, or {@code null} when it reported none.
     * @return {@code true} when the provider is trusted and its {@code amr} contains {@value #MFA_AMR}.
     */
    public boolean isStrong(final Collection<String> upstreamAmr) {
        return trustMfa && upstreamAmr != null
                && upstreamAmr.stream().filter(Objects::nonNull).anyMatch(MFA_AMR::equals);
    }
}
