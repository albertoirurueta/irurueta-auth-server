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

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Reads what is posted to {@code POST /login/ott}: the {@code token} field holds either the token of a magic link (a
 * UUID, which {@link OttLinkAuthenticationProvider} consumes) or the numeric code of an e-mail or SMS, which is tied
 * to the identifier and the binding id the session of the browser holds. A code posted from a browser that requested
 * none is still converted (with an empty identifier), so the provider rejects it like any wrong code instead of the
 * filter ignoring the request.
 */
public class OttAuthenticationConverter implements AuthenticationConverter {

    /** Name of the field that holds the token or the code. */
    public static final String TOKEN_PARAMETER = "token";

    /**
     * Converts the post.
     *
     * @param request the request.
     * @return the request to verify, or {@code null} when no token was posted.
     */
    @Override
    public Authentication convert(final HttpServletRequest request) {
        final var value = StringUtils.trimWhitespace(request.getParameter(TOKEN_PARAMETER));
        if (!StringUtils.hasText(value)) {
            return null;
        }
        if (!OttCodeAuthenticationToken.isCode(value)) {
            return new OneTimeTokenAuthenticationToken(value);
        }
        final var pending = PendingOtt.of(request);
        return new OttCodeAuthenticationToken(pending.map(PendingOtt::identifier).orElse(""), value,
                pending.map(PendingOtt::bindingId).orElse(""));
    }
}
