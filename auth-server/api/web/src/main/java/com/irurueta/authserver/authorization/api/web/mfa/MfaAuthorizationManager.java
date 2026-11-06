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

import com.irurueta.authserver.authorization.application.mfa.IsUserMfaRequiredUseCase;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.FactorAuthorizationDecision;
import org.springframework.security.authorization.RequiredFactor;
import org.springframework.security.authorization.RequiredFactorError;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Decides whether an authentication has presented enough factors for the request being served: when the client or the
 * user requires multi-factor authentication, the factors must satisfy the {@link MfaPolicy}; otherwise any
 * authentication does. A refusal names the second factors that are missing, so Spring Security can send the user to
 * the page that collects them.
 */
@RequiredArgsConstructor
public class MfaAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    /**
     * Name of the custom client setting that makes multi-factor authentication mandatory for a client. It is the same
     * name the persistence adapter writes (that module cannot be referenced from here).
     */
    public static final String CLIENT_MFA_REQUIRED_SETTING = "settings.client.mfa.required";

    /** Policy that decides which factors are enough and when a second factor is required. */
    private final MfaPolicy mfaPolicy;

    /** Registry of the known factors. */
    private final AuthenticationFactorRegistry factorRegistry;

    /** Use case that tells whether a user's account requires a second factor. */
    private final IsUserMfaRequiredUseCase isUserMfaRequiredUseCase;

    /** Repository the client of a request is resolved from. */
    private final RegisteredClientRepository registeredClientRepository;

    /**
     * Decides for a request, taking the client from its {@code client_id} parameter.
     *
     * @param authentication supplier of the current authentication.
     * @param context        the request being served.
     * @return the decision: granted, refused, or refused naming the missing second factors.
     */
    @Override
    public AuthorizationResult authorize(final Supplier<? extends Authentication> authentication,
                                         final RequestAuthorizationContext context) {
        final var current = authentication.get();
        if (!isUser(current)) {
            return new AuthorizationDecision(false);
        }
        final var clientId = context.getRequest().getParameter(OAuth2ParameterNames.CLIENT_ID);
        final var client = clientId == null ? null : registeredClientRepository.findByClientId(clientId);
        return evaluate(current, requiresMfa(client));
    }

    /**
     * Tells whether a client makes multi-factor authentication mandatory.
     *
     * @param client the client, may be {@code null} when unknown.
     * @return {@code true} when its {@link #CLIENT_MFA_REQUIRED_SETTING} setting is true.
     */
    public static boolean requiresMfa(final RegisteredClient client) {
        if (client == null) {
            return false;
        }
        final Object setting = client.getClientSettings().getSetting(CLIENT_MFA_REQUIRED_SETTING);
        return Boolean.TRUE.equals(setting);
    }

    /**
     * Decides for an authentication.
     *
     * @param authentication the authenticated user.
     * @param clientRequires whether the client being served requires multi-factor authentication.
     * @return granted when MFA is not required or the factors satisfy the policy; otherwise refused, naming the
     *         registered second factors as missing (or a plain refusal when none is registered).
     */
    public AuthorizationResult evaluate(final Authentication authentication, final boolean clientRequires) {
        final var userRequires = isUserMfaRequiredUseCase.execute(authentication.getName());
        if (!mfaPolicy.isRequired(clientRequires, userRequires)
                || mfaPolicy.isSatisfied(factorRegistry.factorsOf(authentication))) {
            return new AuthorizationDecision(true);
        }
        final var missing = factorRegistry.withStrength(FactorStrength.SECOND).stream()
                .map(factor -> RequiredFactor.withAuthority(factor.authority()).build())
                .map(RequiredFactorError::createMissing)
                .toList();
        return missing.isEmpty() ? new AuthorizationDecision(false) : new FactorAuthorizationDecision(missing);
    }

    /**
     * Tells whether an authentication is a signed-in user (not missing, unauthenticated or anonymous).
     *
     * @param authentication the authentication, may be {@code null}.
     * @return {@code true} for a signed-in user.
     */
    public static boolean isUser(final Authentication authentication) {
        return authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }
}
