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

package com.irurueta.authserver.authorization.api.web.mfa;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * Resolves the identifier of the account of a signed-in user. The principal Spring Security keeps after a password
 * sign-in carries only the username, while the second-factor use cases work with the account identifier.
 */
@Component
@RequiredArgsConstructor
public class SecondFactorUserResolver {

    /** Use case that looks the account up. */
    private final FindUserAccountUseCase findUserAccountUseCase;

    /**
     * Gets the identifier of an account.
     *
     * @param username name the user signed in with.
     * @return the identifier of the account.
     * @throws UsernameNotFoundException if there is no such account.
     */
    public UUID userIdOf(final String username) {
        return findUserAccountUseCase.execute(username)
                .map(UserAccount::id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}
