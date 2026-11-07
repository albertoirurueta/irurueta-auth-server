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

import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Removes the phone of a user, verified and pending.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class RemovePhoneUseCase {

    /** Port that stores the verified phones. */
    private final UserPhoneRepository userPhoneRepository;

    /** Port that stores the pending verifications. */
    private final PhoneVerificationRepository phoneVerificationRepository;

    /**
     * Removes the phone and any pending verification of a user.
     *
     * @param userId identifier of the user.
     */
    public void execute(final UUID userId) {
        userPhoneRepository.deleteByUserId(userId);
        phoneVerificationRepository.deleteByUserId(userId);
    }
}
