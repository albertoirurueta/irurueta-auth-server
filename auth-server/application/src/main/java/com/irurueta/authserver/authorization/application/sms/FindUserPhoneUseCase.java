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

import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Finds the verified phone of a user, which the account API shows masked.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class FindUserPhoneUseCase {

    /** Port that reads the verified phones. */
    private final UserPhoneRepository userPhoneRepository;

    /**
     * Finds the verified phone of a user.
     *
     * @param userId identifier of the user.
     * @return the phone, or empty when the user has none.
     */
    public Optional<UserPhone> execute(final UUID userId) {
        return userPhoneRepository.findByUserId(userId);
    }
}
