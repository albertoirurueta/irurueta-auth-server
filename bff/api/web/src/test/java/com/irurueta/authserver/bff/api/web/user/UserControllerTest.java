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

package com.irurueta.authserver.bff.api.web.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Unit tests of {@link UserController}.
 */
@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    /** Subject used by the tests. */
    private static final String SUBJECT = "demo-user";

    /** The authenticated OIDC user. */
    @Mock
    private OidcUser oidcUser;

    /** Real mapper onto the generated DTO, spied so the controller is wired with it. */
    @Spy
    private SessionUserDtoMapper sessionUserDtoMapper = new SessionUserDtoMapper();

    /** Controller under test. */
    @InjectMocks
    private UserController controller;

    /** Clears the user signed in by a test, so it never leaks into another one. */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that the response carries the subject of the user signed in to the session.
     */
    @Test
    void getSessionUser_whenUserIsAuthenticated_returnsItsSubject() {
        when(oidcUser.getSubject()).thenReturn(SUBJECT);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(oidcUser, null));

        final var response = controller.getSessionUser();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(SUBJECT, response.getBody().subject());
    }

    /**
     * Verifies that a call without a signed-in user is rejected as unauthenticated.
     */
    @Test
    void getSessionUser_whenNobodyIsSignedIn_throwsAuthenticationCredentialsNotFoundException() {
        assertThrows(AuthenticationCredentialsNotFoundException.class, controller::getSessionUser);
    }

    /**
     * Verifies that a principal other than an OIDC user is rejected as unauthenticated.
     */
    @Test
    void getSessionUser_whenPrincipalIsNotAnOidcUser_throwsAuthenticationCredentialsNotFoundException() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(SUBJECT, null));

        assertThrows(AuthenticationCredentialsNotFoundException.class, controller::getSessionUser);
    }
}
