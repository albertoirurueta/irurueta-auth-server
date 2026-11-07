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
package com.irurueta.authserver.authorization.infrastructure.github;

import com.irurueta.authserver.authorization.domain.social.VerifiedEmailLookup;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;

// tag::github-verified-email[]
/**
 * {@link VerifiedEmailLookup} over GitHub's {@code GET /user/emails}, called through the client generated from
 * {@code apis/github/rest-server/github-api-v1.yaml}. The {@code email} of GitHub's profile is whatever the user chose
 * to show and is not verified, so the address is read from that endpoint, which flags each address as primary and
 * verified.
 *
 * <p>The base URI of the API is the user-info URI of the registration without its trailing {@code /user} (by default
 * {@code https://api.github.com}), so a GitHub Enterprise registration, or the fake provider of the tests, is called
 * where it is. Every failure (GitHub unreachable, an error status, an unreadable body, a user-info URI of another
 * shape) means "no verified address", which refuses the sign-in; it is logged without the token or anything of the
 * user.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GitHubVerifiedEmailLookup implements VerifiedEmailLookup {

    /** Path of the user endpoint below the base URI of GitHub's API. */
    static final String USER_PATH = "/user";

    /** Builds the generated client of each call. */
    private final GitHubUsersApiFactory usersApiFactory;

    /** Picks the verified primary address. */
    private final GitHubEmailMapper emailMapper;

    /**
     * Finds the verified primary address.
     *
     * @param userInfoUri URI of GitHub's user endpoint, as the registration configures it.
     * @param accessToken GitHub access token of the user.
     * @return the address, or an empty optional when there is none or GitHub cannot tell.
     */
    @Override
    public Optional<String> verifiedPrimaryEmail(final String userInfoUri, final String accessToken) {
        final var basePath = basePathOf(userInfoUri);
        if (basePath.isEmpty() || !StringUtils.hasText(accessToken)) {
            log.warn("The e-mail addresses of a GitHub user cannot be read: no usable user-info URI or token");
            return Optional.empty();
        }
        try {
            return emailMapper.verifiedPrimary(
                    usersApiFactory.create(basePath.get(), accessToken).listEmailsForAuthenticatedUser());
        } catch (final RestClientException e) {
            log.warn("The e-mail addresses of a GitHub user could not be read: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    /**
     * Derives the base URI of the API from the user-info URI.
     *
     * @param userInfoUri URI of the user endpoint, possibly {@code null}.
     * @return the URI without its trailing {@code /user} (and slashes), or an empty optional when it does not end so.
     */
    private static Optional<String> basePathOf(final String userInfoUri) {
        if (!StringUtils.hasText(userInfoUri)) {
            return Optional.empty();
        }
        final var trimmed = userInfoUri.strip().replaceFirst("/+$", "");
        if (!trimmed.endsWith(USER_PATH)) {
            return Optional.empty();
        }
        final var basePath = trimmed.substring(0, trimmed.length() - USER_PATH.length());
        return StringUtils.hasText(basePath) ? Optional.of(basePath) : Optional.empty();
    }
}
// end::github-verified-email[]
