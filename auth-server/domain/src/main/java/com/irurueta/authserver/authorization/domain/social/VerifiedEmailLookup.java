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

import java.util.Optional;

// tag::social-verified-email-port[]
/**
 * Port that asks an external provider for the verified primary e-mail address of the user who just signed in, for a
 * provider whose profile does not vouch for its e-mail address (GitHub). It never returns {@code null} and never lets
 * a transport failure escape: a provider that cannot be reached, refuses the token or answers something unreadable
 * means there is no verified address.
 */
public interface VerifiedEmailLookup {

    /**
     * Finds the address that the provider marks as both primary and verified.
     *
     * @param userInfoUri URI of the provider's user endpoint, as the client registration configures it; the addresses
     *                    are read from the same API.
     * @param accessToken access token of the user, issued by the provider during the sign-in.
     * @return the address, or an empty optional when there is none or the provider cannot tell.
     */
    Optional<String> verifiedPrimaryEmail(String userInfoUri, String accessToken);
}
// end::social-verified-email-port[]
