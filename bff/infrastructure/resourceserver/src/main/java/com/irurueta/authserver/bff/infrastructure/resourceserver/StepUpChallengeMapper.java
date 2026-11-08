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
package com.irurueta.authserver.bff.infrastructure.resourceserver;

import com.irurueta.authserver.bff.domain.documents.DocumentsStepUpRequiredException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

/**
 * Maps the {@code WWW-Authenticate} challenge of a {@code 401} answer of the resource server onto the domain: a bearer
 * challenge with {@code error="insufficient_user_authentication"} (RFC 9470) becomes a
 * {@link DocumentsStepUpRequiredException} carrying its {@code acr_values} and {@code max_age}. Any other challenge, or
 * none, is not a step-up request.
 */
@Component
public class StepUpChallengeMapper {

    /** Error code of a step-up challenge (RFC 9470, section 3). */
    static final String INSUFFICIENT_USER_AUTHENTICATION = "insufficient_user_authentication";

    /** Authentication scheme of the challenge. */
    private static final String BEARER = "bearer";

    /** Name of the error parameter of the challenge. */
    private static final String ERROR = "error";

    /** Name of the parameter carrying the authentication context classes asked for. */
    private static final String ACR_VALUES = "acr_values";

    /** Name of the parameter carrying the maximum age of the authentication, in seconds. */
    private static final String MAX_AGE = "max_age";

    /** One auth-param of the challenge: a name and a quoted string (with escapes) or a bare token. */
    private static final Pattern PARAMETER = Pattern.compile(
            "([A-Za-z0-9_-]+)\\s*=\\s*(?:\"((?:[^\"\\\\]|\\\\.)*)\"|([^\\s,\"]+))");

    /** Group of {@link #PARAMETER} holding the parameter name. */
    private static final int NAME_GROUP = 1;

    /** Group of {@link #PARAMETER} holding a quoted value, without its quotes. */
    private static final int QUOTED_VALUE_GROUP = 2;

    /** Group of {@link #PARAMETER} holding a bare token value. */
    private static final int TOKEN_VALUE_GROUP = 3;

    /** Escape sequence of a quoted string: a backslash and the character it protects. */
    private static final Pattern QUOTED_PAIR = Pattern.compile("\\\\(.)");

    /**
     * Reads the step-up request of a {@code 401} answer, if it is one.
     *
     * @param headers headers of the answer; {@code null} when it had none.
     * @param cause   the failure to keep as the cause of the domain exception.
     * @return the step-up request, or empty when the answer carries no step-up challenge.
     */
    public Optional<DocumentsStepUpRequiredException> toException(final HttpHeaders headers, final Throwable cause) {
        if (headers == null) {
            return Optional.empty();
        }
        return headers.getOrEmpty(HttpHeaders.WWW_AUTHENTICATE).stream()
                .filter(StepUpChallengeMapper::isBearer)
                .map(StepUpChallengeMapper::parameters)
                .filter(parameters -> INSUFFICIENT_USER_AUTHENTICATION.equals(parameters.get(ERROR)))
                .findFirst()
                .map(parameters -> new DocumentsStepUpRequiredException(
                        "The resource server asks for a stronger or more recent authentication",
                        parameters.get(ACR_VALUES), maxAgeOf(parameters.get(MAX_AGE)), cause));
    }

    /**
     * Tells whether a challenge is of the bearer scheme.
     *
     * @param challenge value of a {@code WWW-Authenticate} header.
     * @return {@code true} when its scheme is {@code Bearer}, in any case.
     */
    private static boolean isBearer(final String challenge) {
        final var trimmed = challenge.trim();
        return trimmed.length() > BEARER.length()
                && trimmed.substring(0, BEARER.length()).toLowerCase(Locale.ROOT).equals(BEARER)
                && Character.isWhitespace(trimmed.charAt(BEARER.length()));
    }

    /**
     * Reads the auth-params of a bearer challenge.
     *
     * @param challenge value of a {@code WWW-Authenticate} header of the bearer scheme.
     * @return the parameters by lower-case name; a repeated parameter keeps its first value.
     */
    private static Map<String, String> parameters(final String challenge) {
        final var parameters = new HashMap<String, String>();
        final var matcher = PARAMETER.matcher(challenge.trim().substring(BEARER.length()));
        while (matcher.find()) {
            final var quoted = matcher.group(QUOTED_VALUE_GROUP);
            final var value = quoted != null ? QUOTED_PAIR.matcher(quoted).replaceAll("$1")
                    : matcher.group(TOKEN_VALUE_GROUP);
            parameters.putIfAbsent(matcher.group(NAME_GROUP).toLowerCase(Locale.ROOT), value);
        }
        return parameters;
    }

    /**
     * Reads the {@code max_age} parameter.
     *
     * @param value the parameter, in seconds; {@code null} when absent.
     * @return the maximum age, or {@code null} when absent, not a number or negative.
     */
    private static Duration maxAgeOf(final String value) {
        if (value == null || value.isEmpty() || !value.chars().allMatch(Character::isDigit)) {
            return null;
        }
        try {
            return Duration.ofSeconds(Long.parseLong(value));
        } catch (final NumberFormatException e) {
            return null;
        }
    }
}
