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

package com.irurueta.authserver.authorization.api.web.consent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;

import com.irurueta.authserver.authorization.api.web.consent.ConsentPageModel.ScopeView;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Unit tests of {@link ConsentPageModelMapper}.
 */
@ExtendWith(MockitoExtension.class)
class ConsentPageModelMapperTest {

    /** Identifier of the test client. */
    private static final String CLIENT_ID = "app";

    /** Name of the test user. */
    private static final String PRINCIPAL = "demo";

    /** State of the authorization request. */
    private static final String STATE = "xyz";

    /** Resolves the descriptions. */
    @Mock
    private MessageSource messageSource;

    /** Mapper under test. */
    @InjectMocks
    private ConsentPageModelMapper mapper;

    /**
     * Makes the message source describe a scope by its code, so descriptions are predictable.
     */
    @BeforeEach
    void describeScopes() {
        lenient().when(messageSource.getMessage(anyString(), any(), anyString(), eq(Locale.ENGLISH)))
                .thenAnswer(invocation -> "described " + invocation.getArgument(0));
    }

    /**
     * Verifies that the requested scopes are listed, without openid and without the scopes granted earlier.
     */
    @Test
    void toModel_whenScopesAreRequested_listsTheOnesToApproveAndTheOnesGranted() {
        final var model = mapper.toModel(client("App"), PRINCIPAL, STATE, "openid profile email profile",
                Set.of("email", "openid"), Locale.ENGLISH);

        assertEquals(new ConsentPageModel(CLIENT_ID, "App", PRINCIPAL, STATE,
                List.of(new ScopeView("profile", "described consent.scope.profile")),
                List.of(new ScopeView("email", "described consent.scope.email"))), model);
    }

    /**
     * Verifies that blank separators do not produce empty scopes.
     */
    @Test
    void toModel_whenScopeParameterIsBlank_listsNoScope() {
        final var model = mapper.toModel(client("App"), PRINCIPAL, STATE, "  ", Set.of(), Locale.ENGLISH);

        assertEquals(List.of(), model.scopesToApprove());
    }

    /**
     * Verifies that the lists of the model cannot be modified.
     */
    @Test
    void constructor_whenListsAreGiven_copiesThem() {
        final var model = mapper.toModel(client("App"), PRINCIPAL, STATE, "profile", Set.of(), Locale.ENGLISH);

        final var scopes = model.scopesToApprove();
        assertThrows(UnsupportedOperationException.class, () -> scopes.add(new ScopeView("x", "y")));
    }

    /**
     * Builds a client.
     *
     * @param name name of the client.
     * @return the client.
     */
    private static RegisteredClient client(final String name) {
        return RegisteredClient.withId("1").clientId(CLIENT_ID).clientName(name)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://app.example.test/callback").build();
    }
}
