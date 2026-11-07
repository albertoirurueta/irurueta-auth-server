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

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;

/**
 * Hands the session authentication strategy of the chain to the WebAuthn filter. {@code WebAuthnConfigurer} leaves
 * its filter with the do-nothing strategy, so a passkey sign-in would keep the session id of the visitor (session
 * fixation) and the CSRF token it was rendered with. The chain's strategy changes the id and renews the token, as the
 * one of the form login does. The strategy is a shared object that only exists once every configurer has been
 * initialised, and the configurer post-processes its filter while it is configured, so it is read then.
 */
@RequiredArgsConstructor
public class SessionStrategyPostProcessor implements ObjectPostProcessor<WebAuthnAuthenticationFilter> {

    /** Security builder of the chain, whose shared strategy is read. */
    private final HttpSecurity http;

    /**
     * Sets the shared strategy, when the chain has one, on the filter.
     *
     * @param filter the filter the configurer built.
     * @param <O>    type of the filter.
     * @return the same filter.
     */
    @Override
    public <O extends WebAuthnAuthenticationFilter> O postProcess(final O filter) {
        final var strategy = http.getSharedObject(SessionAuthenticationStrategy.class);
        if (strategy != null) {
            filter.setSessionAuthenticationStrategy(strategy);
        }
        return filter;
    }
}
