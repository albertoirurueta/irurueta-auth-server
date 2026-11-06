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

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// tag::mfa-client-required[]
/**
 * Use case that tells whether a client makes multi-factor authentication mandatory for every user signing in through
 * it ({@link ClientRegistration#mfaRequired()}). How the flag is stored is the business of the client port's adapter
 * alone.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class IsClientMfaRequiredUseCase {

    /** Port that stores the clients. */
    private final ClientRegistrationRepository clientRegistrationRepository;

    /**
     * Tells whether a client requires a second factor.
     *
     * @param clientId public identifier of the client, or {@code null} when the request names none.
     * @return {@code true} when the client is registered and requires it; {@code false} otherwise.
     */
    public boolean execute(final String clientId) {
        return clientId != null && clientRegistrationRepository.findByClientId(clientId)
                .map(ClientRegistration::mfaRequired)
                .orElse(false);
    }
}
// end::mfa-client-required[]
