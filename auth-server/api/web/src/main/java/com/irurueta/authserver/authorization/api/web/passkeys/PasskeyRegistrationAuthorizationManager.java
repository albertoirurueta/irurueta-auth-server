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

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Lets a request to the registration endpoints of the WebAuthn filters ({@code /webauthn/register} and everything
 * below it) through only when the session satisfies the multi-factor policy of its account.
 *
 * <p>Registering a passkey adds a factor that, on its own, signs the account in (it is a strong primary factor). A
 * session that only presented the password of an account that still has to complete its second factor must therefore
 * not be able to register one: it could enrol a passkey it controls and sign in with it, skipping the second factor.
 * Spring's own creation-options filter only demands an authenticated user and answers before the chain's
 * authorization filter, so the rule cannot be written as a request matcher of the chain; this manager is installed in
 * an {@code AuthorizationFilter} placed right before it.
 */
@RequiredArgsConstructor
public class PasskeyRegistrationAuthorizationManager implements AuthorizationManager<HttpServletRequest> {

    /** Path of the registration endpoints of the WebAuthn filters. */
    public static final String REGISTRATION_PATH = "/webauthn/register";

    /** Matches the registration endpoints: the options, the registration itself and the removal of a credential. */
    private static final RequestMatcher REGISTRATION = new OrRequestMatcher(
            PathPatternRequestMatcher.pathPattern(REGISTRATION_PATH),
            PathPatternRequestMatcher.pathPattern(REGISTRATION_PATH + "/**"));

    /** Applies the multi-factor policy. */
    private final MfaAuthorizationManager mfaAuthorizationManager;

    /**
     * Decides for a request.
     *
     * @param authentication supplier of the current authentication.
     * @param request        the request being served.
     * @return granted for a request that is not a registration endpoint; for one that is, the decision of the
     *         multi-factor policy (granted only to a signed-in user whose session satisfies it, otherwise refused,
     *         naming the missing second factors so the user is sent to the second-factor page).
     */
    @Override
    public AuthorizationResult authorize(final Supplier<? extends Authentication> authentication,
            final HttpServletRequest request) {
        if (!REGISTRATION.matches(request)) {
            return new AuthorizationDecision(true);
        }
        return mfaAuthorizationManager.authorize(authentication, new RequestAuthorizationContext(request));
    }
}
