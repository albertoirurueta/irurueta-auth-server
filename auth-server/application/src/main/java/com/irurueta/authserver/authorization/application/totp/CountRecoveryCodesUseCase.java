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

package com.irurueta.authserver.authorization.application.totp;

import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that counts the recovery codes a user still has, so the UI can warn when few are left.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class CountRecoveryCodesUseCase {

    /** Port that stores the recovery codes. */
    private final RecoveryCodeRepository recoveryCodeRepository;

    /**
     * Counts the unused codes.
     *
     * @param userId identifier of the user.
     * @return the number of unused codes.
     */
    public int execute(final UUID userId) {
        return recoveryCodeRepository.findUnused(userId).size();
    }
}
