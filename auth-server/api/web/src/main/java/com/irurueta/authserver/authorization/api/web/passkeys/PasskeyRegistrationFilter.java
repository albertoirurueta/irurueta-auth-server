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

package com.irurueta.authserver.authorization.api.web.passkeys;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

/**
 * The authorization filter that guards the registration endpoints of the WebAuthn filters. It is a class of its own
 * (an {@link AuthorizationFilter} with the manager of {@link PasskeyRegistrationAuthorizationManager}) because a
 * second instance of {@code AuthorizationFilter} itself would share the position of the chain's own one, while this
 * class is registered right before it, where Spring's creation-options filter also sits and, being added earlier,
 * runs after this one.
 */
public class PasskeyRegistrationFilter extends AuthorizationFilter {

    /**
     * Creates the filter.
     *
     * @param authorizationManager manager that decides which requests may pass.
     */
    public PasskeyRegistrationFilter(final AuthorizationManager<HttpServletRequest> authorizationManager) {
        super(authorizationManager);
    }
}
