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

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * What a request to {@code POST /ott/generate} asks for, read from its form fields: through which channel, a numeric
 * code or a magic link, and for a sign-in or as a second factor. Every unknown or missing value falls back to the
 * default (an e-mail code for a sign-in), so a malformed request is answered like any other.
 *
 * @param channel channel the token is delivered through.
 * @param kind    whether the token is a numeric code or a magic link.
 * @param purpose whether the token signs the user in or is a second factor of a signed-in user.
 */
public record OttGenerationParameters(OttChannel channel, OttKind kind, OttPurpose purpose) {

    /** Name of the field that holds the identifier (the user name) of a sign-in. */
    public static final String USERNAME_PARAMETER = "username";

    /** Name of the field that holds the channel, {@code email} (default) or {@code sms}. */
    public static final String CHANNEL_PARAMETER = "channel";

    /** Name of the field that holds the kind of token, {@code code} (default) or {@code link}. */
    public static final String KIND_PARAMETER = "kind";

    /** Name of the field that holds the purpose, {@code login} (default) or {@code second-factor}. */
    public static final String PURPOSE_PARAMETER = "purpose";

    /** Value of the channel field that selects SMS. */
    public static final String SMS_VALUE = "sms";

    /** Value of the kind field that selects a magic link. */
    public static final String LINK_VALUE = "link";

    /** Value of the purpose field that selects the second factor. */
    public static final String SECOND_FACTOR_VALUE = "second-factor";

    /**
     * Reads the parameters of a request. A magic link is only sent by e-mail, so an SMS request is always a code, and
     * a second factor is only possible for a user who is signed in: for anybody else the request is a sign-in.
     *
     * @param request the request.
     * @param current the authentication of the request, or {@code null}.
     * @return the parameters.
     */
    public static OttGenerationParameters from(final HttpServletRequest request, final Authentication current) {
        final var sms = SMS_VALUE.equals(lowerCase(request.getParameter(CHANNEL_PARAMETER)));
        final var link = !sms && LINK_VALUE.equals(lowerCase(request.getParameter(KIND_PARAMETER)));
        final var secondFactor = SECOND_FACTOR_VALUE.equals(lowerCase(request.getParameter(PURPOSE_PARAMETER)))
                && isSignedIn(current);
        return new OttGenerationParameters(sms ? OttChannel.SMS : OttChannel.EMAIL,
                link ? OttKind.LINK : OttKind.CODE, secondFactor ? OttPurpose.SECOND_FACTOR : OttPurpose.LOGIN);
    }

    /**
     * Tells whether an authentication is a signed-in user.
     *
     * @param authentication the authentication, or {@code null}.
     * @return {@code true} when it is authenticated and not anonymous.
     */
    static boolean isSignedIn(final Authentication authentication) {
        return authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }

    /**
     * Lower-cases a value, whatever the platform's locale is.
     *
     * @param value the value, or {@code null}.
     * @return the value in lower case; the empty text for {@code null}.
     */
    private static String lowerCase(final String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
