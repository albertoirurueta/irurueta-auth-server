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
package com.irurueta.authserver.authorization.api.web.implicit;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;

// tag::device-guard[]
/**
 * Guards the device verification endpoint. It is installed first among the converters of the endpoint and never
 * converts anything: it either lets the request go on (returning {@code null}) or refuses it. Every request that
 * carries a user code (the code typed on the verification page, a link that carries it, and the consent decision) is
 * counted against the limit on the attempts, and the multi-factor policy of the account (and of the client, when the
 * request names it, as the consent decision does) must be satisfied, as the authorization endpoint requires before it
 * issues a code: a user who owes a second factor is sent to the second-factor page and resumes afterwards. The
 * framework's own MFA customizer covers only {@code /oauth2/authorize}.
 */
@RequiredArgsConstructor
public class DeviceVerificationRequestGuard implements AuthenticationConverter {

    /** Limits the attempts. */
    private final DeviceVerificationRateLimiter rateLimiter;

    /** Applies the multi-factor policy. */
    private final MfaAuthorizationManager authorizationManager;

    /**
     * Checks the request.
     *
     * @param request the request.
     * @return always {@code null}: this converter only vetoes requests.
     * @throws DeviceVerificationRateLimitedException if the client address or the user made too many attempts.
     * @throws SecondFactorRequiredException          if the user still owes a second factor.
     */
    @Override
    public Authentication convert(final HttpServletRequest request) {
        final var user = SecurityContextHolder.getContext().getAuthentication();
        if (!MfaAuthorizationManager.isUser(user)) {
            return null;
        }
        rateLimiter.check(request.getRemoteAddr(), user.getName());
        final var clientRequires = authorizationManager.clientRequiresMfa(
                request.getParameter(OAuth2ParameterNames.CLIENT_ID));
        if (!authorizationManager.evaluate(user, clientRequires).isGranted()) {
            throw new SecondFactorRequiredException();
        }
        return null;
    }
}
// end::device-guard[]
