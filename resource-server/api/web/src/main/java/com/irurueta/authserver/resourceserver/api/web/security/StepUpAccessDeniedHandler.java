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

package com.irurueta.authserver.resourceserver.api.web.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Answers a {@link StepUpRequiredDecision} with {@code 401} and the RFC 9470 challenge
 * ({@code error="insufficient_user_authentication"} with the required {@code acr_values} and {@code max_age});
 * every other denial goes to the delegate, the RFC 6750 handler.
 */
// tag::resource-server-step-up-handler[]
@RequiredArgsConstructor
public class StepUpAccessDeniedHandler implements AccessDeniedHandler {

    /** Handler of every denial that is not a step-up requirement. */
    private final AccessDeniedHandler delegate;

    /** Step-up policy, whose values are advertised in the challenge. */
    private final StepUpProperties properties;

    @Override
    public void handle(final HttpServletRequest request, final HttpServletResponse response,
            final AccessDeniedException accessDeniedException) throws IOException, ServletException {
        if (accessDeniedException instanceof AuthorizationDeniedException denied
                && denied.getAuthorizationResult() instanceof StepUpRequiredDecision) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"insufficient_user_authentication\", "
                    + "acr_values=\"" + properties.acrValues() + "\", max_age=\""
                    + properties.maxAge().toSeconds() + "\"");
            return;
        }
        delegate.handle(request, response, accessDeniedException);
    }
}
// end::resource-server-step-up-handler[]
