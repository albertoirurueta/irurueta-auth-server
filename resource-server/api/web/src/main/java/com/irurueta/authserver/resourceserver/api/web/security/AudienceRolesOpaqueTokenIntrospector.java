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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

/**
 * Decorates an introspector of the opaque-token variant: rejects tokens whose audience is not accepted and adds the
 * role authorities of the {@code roles} attribute, so the opaque variant behaves like the JWT one.
 */
@RequiredArgsConstructor
public class AudienceRolesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    /** Introspector that calls the authorization server. */
    private final OpaqueTokenIntrospector delegate;

    /** Audiences this resource server accepts. */
    private final List<String> acceptedAudiences;

    @Override
    public OAuth2AuthenticatedPrincipal introspect(final String token) {
        final var principal = delegate.introspect(token);
        final List<String> audiences = principal.getAttribute(OAuth2TokenIntrospectionClaimNames.AUD);
        if (audiences == null || audiences.stream().noneMatch(acceptedAudiences::contains)) {
            throw new BadOpaqueTokenException("The token was not issued for this resource server");
        }
        final List<String> roles = principal.getAttribute(BearerAuthorities.ROLES_CLAIM);
        final Collection<GrantedAuthority> authorities = new ArrayList<>(principal.getAuthorities());
        authorities.addAll(BearerAuthorities.roleAuthorities(roles));
        return new DefaultOAuth2AuthenticatedPrincipal(principal.getName(), principal.getAttributes(), authorities);
    }
}
