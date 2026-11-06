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
package com.irurueta.authserver.authorization.api.web.totp;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Success handler of the second-factor post: when the post confirmed an enrolment and recovery codes are waiting to be
 * shown, the browser goes to the page that shows them once (whose "Continue" button resumes the interrupted request);
 * otherwise the delegate resumes the interrupted request straight away.
 */
@RequiredArgsConstructor
public class RecoveryCodesSuccessHandler implements AuthenticationSuccessHandler {

    /** Strategy that redirects, honouring the context path. */
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /** Keeps the codes waiting to be shown. */
    private final PendingRecoveryCodes pendingRecoveryCodes;

    /** Handler that resumes the interrupted request. */
    private final AuthenticationSuccessHandler delegate;

    /**
     * Redirects to the recovery codes page or resumes the interrupted request.
     *
     * @param request        the request.
     * @param response       the response.
     * @param authentication the verified authentication.
     * @throws IOException      if the redirect cannot be sent.
     * @throws ServletException if the delegate fails.
     */
    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) throws IOException, ServletException {
        if (pendingRecoveryCodes.isPending(request)) {
            redirectStrategy.sendRedirect(request, response, RecoveryCodesPageController.RECOVERY_CODES_PATH);
            return;
        }
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}
