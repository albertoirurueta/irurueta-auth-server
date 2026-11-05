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

package com.irurueta.authserver.resourceserver.api.web.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

/**
 * Unit tests for {@link AudienceRolesOpaqueTokenIntrospector}.
 */
@ExtendWith(MockitoExtension.class)
class AudienceRolesOpaqueTokenIntrospectorTest {

    /** Opaque token used by the tests. */
    private static final String TOKEN = "opaque-value";

    /** Accepted audience. */
    private static final String AUDIENCE = "resource-server";

    /** Mocked delegate. */
    @Mock
    private OpaqueTokenIntrospector delegate;

    /** Roles are added next to the scopes when the audience is accepted. */
    @Test
    void introspect_whenAudienceIsAccepted_addsRoleAuthorities() {
        when(delegate.introspect(TOKEN)).thenReturn(new DefaultOAuth2AuthenticatedPrincipal("alice",
                Map.of("aud", List.of(AUDIENCE), "roles", List.of("ADMIN")),
                List.of(new SimpleGrantedAuthority("SCOPE_documents.read"))));

        final var principal = new AudienceRolesOpaqueTokenIntrospector(delegate, List.of(AUDIENCE)).introspect(TOKEN);

        assertEquals(List.of("SCOPE_documents.read", "ROLE_ADMIN"),
                principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        assertEquals("alice", principal.getName());
    }

    /** A token without roles keeps its own authorities. */
    @Test
    void introspect_whenThereAreNoRoles_keepsTheScopes() {
        when(delegate.introspect(TOKEN)).thenReturn(new DefaultOAuth2AuthenticatedPrincipal("alice",
                Map.of("aud", List.of(AUDIENCE)), List.of(new SimpleGrantedAuthority("SCOPE_documents.read"))));

        final var principal = new AudienceRolesOpaqueTokenIntrospector(delegate, List.of(AUDIENCE)).introspect(TOKEN);

        assertEquals(1, principal.getAuthorities().size());
    }

    /** Another audience is rejected. */
    @Test
    void introspect_whenAudienceIsOther_throwsBadOpaqueTokenException() {
        when(delegate.introspect(TOKEN)).thenReturn(new DefaultOAuth2AuthenticatedPrincipal("alice",
                Map.of("aud", List.of("other")), List.of()));
        final var introspector = new AudienceRolesOpaqueTokenIntrospector(delegate, List.of(AUDIENCE));

        assertThrows(BadOpaqueTokenException.class, () -> introspector.introspect(TOKEN));
    }

    /** A token without audience is rejected. */
    @Test
    void introspect_whenThereIsNoAudience_throwsBadOpaqueTokenException() {
        when(delegate.introspect(TOKEN)).thenReturn(new DefaultOAuth2AuthenticatedPrincipal("alice",
                Map.of("sub", "alice"), List.of()));
        final var introspector = new AudienceRolesOpaqueTokenIntrospector(delegate, List.of(AUDIENCE));

        assertThrows(BadOpaqueTokenException.class, () -> introspector.introspect(TOKEN));
    }
}
