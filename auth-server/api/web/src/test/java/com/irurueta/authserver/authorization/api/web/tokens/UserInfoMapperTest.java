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

package com.irurueta.authserver.authorization.api.web.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;

/**
 * Unit tests of {@link UserInfoMapper}.
 */
class UserInfoMapperTest {

    /** Username of the test user. */
    private static final String USERNAME = "alice";

    /** E-mail address of the test user. */
    private static final String EMAIL = "alice@example.com";

    /** Tenant of the test user. */
    private static final String TENANT = "acme";

    /** Role of the test user. */
    private static final String ROLE = "ROLE_USER";

    /** Finds accounts. */
    private FindUserAccountUseCase findUserAccountUseCase;

    /** Subject under test. */
    private UserInfoMapper mapper;

    /**
     * Creates the subject with a mocked use case.
     */
    @BeforeEach
    void setUp() {
        findUserAccountUseCase = mock(FindUserAccountUseCase.class);
        mapper = new UserInfoMapper(findUserAccountUseCase);
    }

    /**
     * Profile and e-mail scopes expose every claim.
     */
    @Test
    void apply_whenProfileAndEmailScopes_returnsAllClaims() {
        givenAccount(EMAIL);

        final var claims = mapper.apply(context("openid", "profile", "email")).getClaims();

        assertEquals(USERNAME, claims.get("sub"));
        assertEquals(USERNAME, claims.get("preferred_username"));
        assertEquals(List.of(ROLE), claims.get("roles"));
        assertEquals(TENANT, claims.get("tenant"));
        assertEquals(EMAIL, claims.get("email"));
        assertEquals(true, claims.get("email_verified"));
    }

    /**
     * Only the openid scope exposes the subject.
     */
    @Test
    void apply_whenOnlyOpenidScope_returnsSubjectOnly() {
        givenAccount(EMAIL);

        final var claims = mapper.apply(context("openid")).getClaims();

        assertEquals(1, claims.size());
        assertEquals(USERNAME, claims.get("sub"));
    }

    /**
     * An account without e-mail exposes no e-mail claims even with the e-mail scope.
     */
    @Test
    void apply_whenAccountHasNoEmail_omitsEmailClaims() {
        givenAccount(null);

        final var claims = mapper.apply(context("openid", "email")).getClaims();

        assertFalse(claims.containsKey("email"));
        assertFalse(claims.containsKey("email_verified"));
    }

    /**
     * An unknown account yields the subject only.
     */
    @Test
    void apply_whenAccountIsMissing_returnsSubjectOnly() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.empty());

        final var claims = mapper.apply(context("openid", "profile")).getClaims();

        assertTrue(claims.containsKey("sub"));
        assertEquals(1, claims.size());
    }

    /**
     * Makes the use case find an account.
     *
     * @param email e-mail address of the account.
     */
    private void givenAccount(final String email) {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(new UserAccount(
                UUID.randomUUID(), USERNAME, "x", true, List.of(ROLE), email, true, TENANT)));
    }

    /**
     * Creates a mocked context for the user and the scopes.
     *
     * @param scopes granted scopes.
     * @return the context.
     */
    private static OidcUserInfoAuthenticationContext context(final String... scopes) {
        final var authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn(USERNAME);
        final var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "t", Instant.now(),
                Instant.now().plusSeconds(1), Set.of(scopes));
        final var context = mock(OidcUserInfoAuthenticationContext.class);
        when(context.getAuthorization()).thenReturn(authorization);
        when(context.getAccessToken()).thenReturn(token);
        return context;
    }
}
