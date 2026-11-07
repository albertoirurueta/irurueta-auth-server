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

package com.irurueta.authserver.authorization.application.ott;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Finds where a one-time code of a user may be delivered: the verified e-mail address or the verified phone of an
 * enabled account. Anything else yields an empty result, without saying why.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ResolveOttDestinationUseCase {

    /** Use case that finds an account. */
    private final FindUserAccountUseCase findUserAccountUseCase;

    /** Port that reads the verified phones. */
    private final UserPhoneRepository userPhoneRepository;

    /**
     * Resolves the destination of a user.
     *
     * @param username name the user signs in with.
     * @param channel  the channel.
     * @return the destination, or empty when the account is unknown or disabled or has no verified address for the
     *         channel.
     */
    public Optional<OttDestination> execute(final String username, final OttChannel channel) {
        if (!StringUtils.hasText(username)) {
            return Optional.empty();
        }
        return findUserAccountUseCase.execute(username)
                .filter(UserAccount::enabled)
                .flatMap(account -> addressOf(account, channel)
                        .map(address -> new OttDestination(account.id(), channel, address)));
    }

    /**
     * Reads the verified address of an account for a channel.
     *
     * @param account the account.
     * @param channel the channel.
     * @return the address, or empty when there is no verified one.
     */
    private Optional<String> addressOf(final UserAccount account, final OttChannel channel) {
        return switch (channel) {
            case EMAIL -> Optional.ofNullable(account.email())
                    .filter(email -> account.emailVerified() && StringUtils.hasText(email));
            case SMS -> userPhoneRepository.findByUserId(account.id()).map(phone -> phone.phone().e164());
        };
    }
}
