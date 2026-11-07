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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.infrastructure.github.v1.generated.api.UsersApi;
import com.irurueta.authserver.authorization.infrastructure.github.v1.generated.model.Email;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.client.ResourceAccessException;

/**
 * Unit tests of {@link GitHubVerifiedEmailLookup}, with the client factory, the generated client and the mapper mocked.
 */
@ExtendWith(MockitoExtension.class)
class GitHubVerifiedEmailLookupTest {

    /** Base URI of the API. */
    private static final String BASE_PATH = "https://api.github.test";

    /** User-info URI of the registration. */
    private static final String USER_INFO_URI = BASE_PATH + "/user";

    /** Access token of the tests. */
    private static final String TOKEN = "token";

    /** The address of the tests. */
    private static final String ADDRESS = "main@example.org";

    /** Builds the generated client. */
    @Mock
    private GitHubUsersApiFactory usersApiFactory;

    /** The generated client. */
    @Mock
    private UsersApi usersApi;

    /** Picks the address. */
    @Mock
    private GitHubEmailMapper emailMapper;

    /** Lookup under test. */
    @InjectMocks
    private GitHubVerifiedEmailLookup lookup;

    /**
     * Verifies that the base URI is the user-info URI without {@code /user}, and that the answer goes through the
     * mapper.
     */
    @Test
    void verifiedPrimaryEmail_whenGitHubAnswers_mapsTheAnswer() {
        final var emails = List.of(new Email().email(ADDRESS).primary(true).verified(true));
        when(usersApiFactory.create(BASE_PATH, TOKEN)).thenReturn(usersApi);
        when(usersApi.listEmailsForAuthenticatedUser()).thenReturn(emails);
        when(emailMapper.verifiedPrimary(any())).thenReturn(Optional.of(ADDRESS));

        assertEquals(Optional.of(ADDRESS), lookup.verifiedPrimaryEmail(USER_INFO_URI, TOKEN));
        final var captor = ArgumentCaptor.<List<Email>>captor();
        verify(emailMapper).verifiedPrimary(captor.capture());
        assertSame(emails, captor.getValue());
    }

    /**
     * Verifies that trailing slashes of the user-info URI are ignored.
     */
    @Test
    void verifiedPrimaryEmail_whenUserInfoUriHasATrailingSlash_usesTheSameBase() {
        when(usersApiFactory.create(BASE_PATH, TOKEN)).thenReturn(usersApi);
        when(usersApi.listEmailsForAuthenticatedUser()).thenReturn(List.of());
        when(emailMapper.verifiedPrimary(any())).thenReturn(Optional.empty());

        assertTrue(lookup.verifiedPrimaryEmail(USER_INFO_URI + "/", TOKEN).isEmpty());
        verify(usersApiFactory).create(BASE_PATH, TOKEN);
    }

    /**
     * Verifies that a failure of the call is no address, never an exception.
     */
    @Test
    void verifiedPrimaryEmail_whenGitHubCannotBeReached_isEmpty() {
        when(usersApiFactory.create(BASE_PATH, TOKEN)).thenReturn(usersApi);
        when(usersApi.listEmailsForAuthenticatedUser()).thenThrow(new ResourceAccessException("down"));

        assertTrue(lookup.verifiedPrimaryEmail(USER_INFO_URI, TOKEN).isEmpty());
        verifyNoInteractions(emailMapper);
    }

    /**
     * Verifies that a user-info URI that does not end with {@code /user}, or is missing, calls nothing.
     */
    @Test
    void verifiedPrimaryEmail_whenUserInfoUriHasAnotherShape_callsNothing() {
        assertTrue(lookup.verifiedPrimaryEmail(BASE_PATH + "/profile", TOKEN).isEmpty());
        assertTrue(lookup.verifiedPrimaryEmail("/user", TOKEN).isEmpty());
        assertTrue(lookup.verifiedPrimaryEmail(null, TOKEN).isEmpty());
        assertTrue(lookup.verifiedPrimaryEmail(" ", TOKEN).isEmpty());

        verifyNoInteractions(usersApiFactory, emailMapper);
    }

    /**
     * Verifies that a missing token calls nothing.
     */
    @Test
    void verifiedPrimaryEmail_whenTokenIsMissing_callsNothing() {
        assertTrue(lookup.verifiedPrimaryEmail(USER_INFO_URI, null).isEmpty());
        assertTrue(lookup.verifiedPrimaryEmail(USER_INFO_URI, "").isEmpty());

        verifyNoInteractions(usersApiFactory, emailMapper);
    }
}
