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

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Resolves the account of the request being handled. The interfaces generated from the contract carry only the
 * parameters the contract declares, so the principal of the bearer token is taken from the request context.
 */
@Component
@RequiredArgsConstructor
public class CurrentAccountResolver {

    /** Resolves the identifier of an account from its username. */
    private final SecondFactorUserResolver secondFactorUserResolver;

    /**
     * Gets the account of the current request.
     *
     * @return the account of the principal of the request.
     * @throws org.springframework.security.core.userdetails.UsernameNotFoundException if the principal has no
     *                                                                                  account.
     */
    public CurrentAccount resolve() {
        final var request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        return resolve(request);
    }

    /**
     * Gets the account of the principal of a request.
     *
     * @param request the request.
     * @return the account.
     */
    private CurrentAccount resolve(final HttpServletRequest request) {
        final var username = request.getUserPrincipal().getName();
        return new CurrentAccount(secondFactorUserResolver.userIdOf(username), username);
    }
}
