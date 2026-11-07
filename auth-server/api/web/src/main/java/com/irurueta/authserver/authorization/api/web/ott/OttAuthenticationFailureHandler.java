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

import com.irurueta.authserver.authorization.api.web.login.LoginController;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.OneTimeTokenPageApi;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.StringUtils;

/**
 * Sends the browser back after a failed submission to {@code POST /login/ott}: a wrong numeric code goes to the page
 * where it is typed ({@code /login/ott?error}), so the user can try again, and a magic link that is not valid goes to
 * the sign-in page ({@code /login?error}). Both keep the failure in the session, as Spring Security does, for the
 * page to show a message that never says whether the account exists or the code was close.
 */
public class OttAuthenticationFailureHandler implements AuthenticationFailureHandler {

    /** Handler of a failed code. */
    private final AuthenticationFailureHandler codeFailure = new SimpleUrlAuthenticationFailureHandler(
            OneTimeTokenPageApi.PATH_OTT_CODE_PAGE + "?error");

    /** Handler of a failed link. */
    private final AuthenticationFailureHandler linkFailure = new SimpleUrlAuthenticationFailureHandler(
            LoginController.LOGIN_PATH + "?error");

    /**
     * Redirects according to what was submitted.
     *
     * @param request   the request.
     * @param response  the response.
     * @param exception the failure.
     * @throws IOException      if the redirect cannot be sent.
     * @throws ServletException if the delegate fails.
     */
    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException exception) throws IOException, ServletException {
        final var value = StringUtils.trimWhitespace(request.getParameter(OttAuthenticationConverter.TOKEN_PARAMETER));
        final var handler = OttCodeAuthenticationToken.isCode(value) ? codeFailure : linkFailure;
        handler.onAuthenticationFailure(request, response, exception);
    }
}
