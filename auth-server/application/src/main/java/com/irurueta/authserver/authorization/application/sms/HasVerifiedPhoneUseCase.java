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

package com.irurueta.authserver.authorization.application.sms;

import com.irurueta.authserver.authorization.application.mfa.SecondFactorEnrolmentQuery;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Tells whether a user has a verified phone. As the enrolment query of the SMS second factor, a user with a verified
 * phone requires multi-factor authentication.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class HasVerifiedPhoneUseCase implements SecondFactorEnrolmentQuery {

    /** Port that reads the verified phones. */
    private final UserPhoneRepository userPhoneRepository;

    /**
     * Tells whether a user has a verified phone.
     *
     * @param userId identifier of the user.
     * @return {@code true} when a phone of the user is verified.
     */
    public boolean execute(final UUID userId) {
        return userPhoneRepository.findByUserId(userId).isPresent();
    }

    /**
     * Tells whether a user has confirmed the SMS second factor.
     *
     * @param userId identifier of the user.
     * @return the same as {@link #execute(UUID)}.
     */
    @Override
    public boolean hasConfirmed(final UUID userId) {
        return execute(userId);
    }
}
