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

package com.irurueta.authserver.authorization.application.passkeys;

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that lists the passkeys of a user.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ListPasskeysUseCase {

    /** Port that reads the passkeys. */
    private final PasskeyRepository passkeyRepository;

    /**
     * Lists the passkeys of an account, oldest first.
     *
     * @param username name of the signed-in account.
     * @return its passkeys; empty when the account never registered one.
     */
    public List<Passkey> execute(final String username) {
        return passkeyRepository.findUserIdByUsername(username).map(passkeyRepository::findByUserId)
                .orElseGet(List::of);
    }
}
