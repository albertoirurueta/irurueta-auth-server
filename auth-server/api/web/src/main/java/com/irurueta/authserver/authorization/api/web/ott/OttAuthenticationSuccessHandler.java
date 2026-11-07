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
package com.irurueta.authserver.authorization.api.web.ott;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Forgets the pending token of the session once it was used, then lets the delegate resume the request the sign-in
 * interrupted.
 */
@RequiredArgsConstructor
public class OttAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    /** Resumes the interrupted request. */
    private final AuthenticationSuccessHandler delegate;

    /**
     * Clears the pending token and delegates.
     *
     * @param request        the request.
     * @param response       the response.
     * @param authentication the authentication.
     * @throws IOException if the delegate cannot redirect.
     * @throws ServletException if the delegate fails.
     */
    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) throws IOException, ServletException {
        PendingOtt.clear(request);
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}
