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

import org.springframework.util.StringUtils;

/**
 * The user name a magic link token is stored with. Spring's token store only keeps a user name next to the token, so
 * the purpose of a link travels in it: the token of a link requested as a second factor starts with a control
 * character that no identifier can carry (identifiers are stripped of control characters before they are used), and
 * {@link OttLinkAuthenticationProvider} accepts it only in the session of the signed-in user it was requested for.
 * The column holds {@value #MAX_LENGTH} characters, so an identifier is cut to what fits; a second-factor link of a
 * user name longer than {@value #MAX_SECOND_FACTOR_LENGTH} characters would be cut and never match its user, so
 * {@link OttGenerationSuccessHandler} does not deliver it ({@link #fitsSecondFactorLink(String)}).
 */
public final class LinkTokenUsername {

    /** Characters the user name column of the token store holds. */
    public static final int MAX_LENGTH = 100;

    /** Characters a user name may have to fit the column next to the marker of a second-factor link. */
    public static final int MAX_SECOND_FACTOR_LENGTH = MAX_LENGTH - 1;

    /** Marker of the token of a link requested as a second factor. */
    static final char SECOND_FACTOR_MARKER = '\u001f';

    /** Utility class: not meant to be instantiated. */
    private LinkTokenUsername() {
    }

    /**
     * Cleans an identifier typed in a form: no control characters, no surrounding blanks, and no more characters than
     * the column holds.
     *
     * @param identifier the identifier, or {@code null}.
     * @return the identifier ready to be stored; the empty text when nothing is left of it.
     */
    public static String clean(final String identifier) {
        if (identifier == null) {
            return "";
        }
        final var cleaned = identifier.chars().filter(character -> !Character.isISOControl(character))
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString().trim();
        return cleaned.length() > MAX_LENGTH ? cleaned.substring(0, MAX_LENGTH) : cleaned;
    }

    /**
     * Builds the stored user name of a link.
     *
     * @param identifier the cleaned identifier.
     * @param secondFactor whether the link is requested as a second factor.
     * @return the identifier, preceded by the marker for a second factor and cut to the column's size.
     */
    public static String forLink(final String identifier, final boolean secondFactor) {
        if (!secondFactor) {
            return identifier;
        }
        final var marked = SECOND_FACTOR_MARKER + identifier;
        return marked.length() > MAX_LENGTH ? marked.substring(0, MAX_LENGTH) : marked;
    }

    /**
     * Tells whether a user name fits the column next to the marker of a second-factor link, so that the stored name of
     * the link still identifies the user.
     *
     * @param username the name of the signed-in user.
     * @return {@code true} when it has at most {@value #MAX_SECOND_FACTOR_LENGTH} characters.
     */
    public static boolean fitsSecondFactorLink(final String username) {
        return username != null && username.length() <= MAX_SECOND_FACTOR_LENGTH;
    }

    /**
     * Tells whether a stored user name is the one of a link requested as a second factor.
     *
     * @param stored the stored user name.
     * @return {@code true} when it carries the marker.
     */
    public static boolean isSecondFactor(final String stored) {
        return StringUtils.hasLength(stored) && stored.charAt(0) == SECOND_FACTOR_MARKER;
    }

    /**
     * Gets the identifier of a stored user name.
     *
     * @param stored the stored user name.
     * @return the identifier, without the marker.
     */
    public static String identifierOf(final String stored) {
        return isSecondFactor(stored) ? stored.substring(1) : stored;
    }
}
