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

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceTokenSigner;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.time.Clock;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// tag::mfa-find-trusted-device[]
/**
 * Use case that finds the usable (not revoked, not expired) trusted device of a user from the value of the cookie.
 * The signature of the value is checked first, in constant time: a forged or unsigned value is rejected before the
 * account or the device is looked up.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class FindTrustedDeviceUseCase {

    /** Port that checks the signature of the cookie value. */
    private final TrustedDeviceTokenSigner trustedDeviceTokenSigner;

    /** Port that provides the user accounts. */
    private final UserAccountRepository userAccountRepository;

    /** Port that stores the trusted devices. */
    private final TrustedDeviceRepository trustedDeviceRepository;

    /** Creator and hasher of the tokens. */
    private final TrustedDeviceTokens trustedDeviceTokens;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Finds the device.
     *
     * @param username    name the user signed in with.
     * @param cookieValue the signed value presented by the browser.
     * @return the device, or empty if the signature is wrong, the account does not exist, or the token is unknown,
     *         expired, revoked or belongs to another user.
     */
    public Optional<TrustedDevice> execute(final String username, final String cookieValue) {
        return trustedDeviceTokenSigner.verify(cookieValue)
                .flatMap(token -> userAccountRepository.findByUsername(username)
                        .flatMap(account -> trustedDeviceRepository.findUsable(
                                account.id(), trustedDeviceTokens.hash(token), clock.instant())
                                .filter(device -> account.id().equals(device.userId()))));
    }
}
// end::mfa-find-trusted-device[]
