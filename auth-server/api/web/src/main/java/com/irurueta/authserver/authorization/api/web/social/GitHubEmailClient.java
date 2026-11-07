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

package com.irurueta.authserver.authorization.api.web.social;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Reads the verified primary e-mail address of a GitHub user. The {@code email} of GitHub's profile is whatever the
 * user chose to show and is not verified, so the address is read from the {@code /user/emails} endpoint, which marks
 * each address as primary and verified; only an address that is both counts.
 */
@Slf4j
@RequiredArgsConstructor
public class GitHubEmailClient {

    /** Media type GitHub's API asks for. */
    static final String GITHUB_MEDIA_TYPE = "application/vnd.github+json";

    /** Name of the flag that marks the primary address. */
    private static final String PRIMARY = "primary";

    /** Name of the flag that marks a verified address. */
    private static final String VERIFIED = "verified";

    /** Name of the address. */
    private static final String EMAIL = "email";

    /** Calls GitHub's API. */
    private final RestClient restClient;

    /**
     * Finds the verified primary address.
     *
     * @param userInfoUri URI of the user endpoint of the registration; the addresses are at {@code /emails} below it.
     * @param accessToken access token of the user.
     * @return the address, or an empty optional when there is none or GitHub cannot be reached. The failure is logged
     *         without any detail of the user.
     */
    public Optional<String> verifiedPrimaryEmail(final String userInfoUri, final String accessToken) {
        try {
            final var emails = restClient.get()
                    .uri(userInfoUri + "/emails")
                    .headers(headers -> {
                        headers.setBearerAuth(accessToken);
                        headers.set(HttpHeaders.ACCEPT, GITHUB_MEDIA_TYPE);
                    })
                    .retrieve()
                    .body(new ParameterizedTypeReference<List<Map<String, Object>>>() { });
            return emails == null ? Optional.empty() : emails.stream()
                    .filter(entry -> Boolean.TRUE.equals(entry.get(PRIMARY))
                            && Boolean.TRUE.equals(entry.get(VERIFIED)))
                    .map(entry -> entry.get(EMAIL))
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .findFirst();
        } catch (final RestClientException e) {
            log.warn("The e-mail addresses of a GitHub user could not be read: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }
}
