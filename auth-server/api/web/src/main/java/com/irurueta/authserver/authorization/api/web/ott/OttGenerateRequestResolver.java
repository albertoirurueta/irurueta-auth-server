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

import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenRequestResolver;
import org.springframework.util.StringUtils;

// tag::ott-generate-resolver[]
/**
 * Resolves the request of {@code POST /ott/generate} to the token Spring's filter asks the token service for. The
 * identifier is the {@code username} field of a sign-in and, for a second factor, the name of the signed-in user (never
 * a field a client could point at somebody else), cleaned of control characters and cut to what the token store
 * holds. The lifetime of the token is the one {@link OttPolicy} sets for its kind. A request that names no identifier
 * is not resolved, so the chain goes on as it would for any other path. Whether the identifier belongs to an account
 * is not looked at here: a token is issued for any identifier, and what is delivered is decided afterwards, so the
 * answer never tells.
 */
@RequiredArgsConstructor
public class OttGenerateRequestResolver implements GenerateOneTimeTokenRequestResolver {

    /** The rules of one-time tokens, which set the lifetime of each kind. */
    private final OttPolicy ottPolicy;

    /**
     * Resolves the request.
     *
     * @param request the request.
     * @return the token to generate, or {@code null} when the request names no identifier.
     */
    @Override
    public GenerateOneTimeTokenRequest resolve(final HttpServletRequest request) {
        final var current = SecurityContextHolder.getContext().getAuthentication();
        final var parameters = OttGenerationParameters.from(request, current);
        final var secondFactor = parameters.purpose() == OttPurpose.SECOND_FACTOR;
        final var identifier = LinkTokenUsername.clean(
                secondFactor ? current.getName() : request.getParameter(OttGenerationParameters.USERNAME_PARAMETER));
        if (!StringUtils.hasText(identifier)) {
            return null;
        }
        final var username = LinkTokenUsername.forLink(identifier,
                secondFactor && parameters.kind() == OttKind.LINK);
        return new GenerateOneTimeTokenRequest(username, ottPolicy.ttl(parameters.kind()));
    }
}
// end::ott-generate-resolver[]
