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
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

// tag::device-guard[]
/**
 * Guards the device verification endpoint. It is installed first among the converters of the endpoint and never
 * converts anything: it either lets the request go on (returning {@code null}) or refuses it. Every request that
 * carries a user code (the code typed on the verification page, a link that carries it, and the consent decision) is
 * counted against the limit on the attempts, and the multi-factor policy of the account and of the client must be
 * satisfied, as the authorization endpoint requires before it issues a code: a user who owes a second factor is sent
 * to the second-factor page and resumes afterwards. The framework's own MFA customizer covers only
 * {@code /oauth2/authorize}.
 *
 * <p>The client is the one the device authorization stored for the user code was issued to, because the code typed on
 * the page (or carried by the link) is the only thing the request names: so a client that requires multi-factor
 * authentication is enforced even when it skips the consent page. Only when no authorization holds the code (an
 * unknown or expired one, which the endpoint refuses anyway) is the {@code client_id} of the consent decision used.
 */
@RequiredArgsConstructor
public class DeviceVerificationRequestGuard implements AuthenticationConverter {

    /** Type of the token the user code is stored as. */
    static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.USER_CODE);

    /** Number of letters and digits of a user code. */
    private static final int USER_CODE_LENGTH = 8;

    /** Position of the dash the framework stores a user code with. */
    private static final int USER_CODE_GROUP = USER_CODE_LENGTH / 2;

    /** Everything a user may type around the letters and digits of a code (dashes, spaces). */
    private static final Pattern NOT_ALPHANUMERIC = Pattern.compile("[^A-Z\\d]+");

    /** Limits the attempts. */
    private final DeviceVerificationRateLimiter rateLimiter;

    /** Applies the multi-factor policy. */
    private final MfaAuthorizationManager authorizationManager;

    /** Finds the device authorization of a user code. */
    private final OAuth2AuthorizationService authorizationService;

    /** Finds the client of a device authorization. */
    private final RegisteredClientRepository registeredClientRepository;

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
        final var clientRequires = authorizationManager.clientRequiresMfa(clientIdOf(request));
        if (!authorizationManager.evaluate(user, clientRequires).isGranted()) {
            throw new SecondFactorRequiredException();
        }
        return null;
    }

    /**
     * Finds the client a request is about: the client of the device authorization stored for its user code, or the
     * {@code client_id} parameter when no authorization holds that code.
     *
     * @param request the request.
     * @return the client id, or {@code null} when neither tells it.
     */
    private String clientIdOf(final HttpServletRequest request) {
        return normalize(request.getParameter(OAuth2ParameterNames.USER_CODE))
                .map(userCode -> authorizationService.findByToken(userCode, USER_CODE_TOKEN_TYPE))
                .map(authorization -> registeredClientRepository.findById(authorization.getRegisteredClientId()))
                .map(RegisteredClient::getClientId)
                .orElseGet(() -> request.getParameter(OAuth2ParameterNames.CLIENT_ID));
    }

    /**
     * Normalises a user code as the framework stores it: upper case letters and digits in two groups of four,
     * separated by a dash.
     *
     * @param userCode the code as typed, may be {@code null}.
     * @return the stored form, or empty when the value cannot be a user code.
     */
    private static Optional<String> normalize(final String userCode) {
        if (!StringUtils.hasText(userCode)) {
            return Optional.empty();
        }
        final var compact = NOT_ALPHANUMERIC.matcher(userCode.toUpperCase(Locale.ROOT)).replaceAll("");
        if (compact.length() != USER_CODE_LENGTH) {
            return Optional.empty();
        }
        return Optional.of(compact.substring(0, USER_CODE_GROUP) + "-" + compact.substring(USER_CODE_GROUP));
    }
}
// end::device-guard[]
