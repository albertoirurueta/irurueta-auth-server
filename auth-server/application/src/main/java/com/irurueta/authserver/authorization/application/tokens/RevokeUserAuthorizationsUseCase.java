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

package com.irurueta.authserver.authorization.application.tokens;

import com.irurueta.authserver.authorization.domain.tokens.UserAuthorizationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that revokes every token of a user, for example after a password change or reset.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class RevokeUserAuthorizationsUseCase {

    /** Port that removes stored authorizations. */
    private final UserAuthorizationRepository userAuthorizationRepository;

    /**
     * Deletes the authorizations granted to a user.
     *
     * @param principalName name of the user.
     * @return the number of revoked authorizations.
     */
    public int execute(final String principalName) {
        return userAuthorizationRepository.deleteByPrincipalName(principalName);
    }
}
