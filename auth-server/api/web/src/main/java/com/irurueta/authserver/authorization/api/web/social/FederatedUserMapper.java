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

import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

// tag::social-user-mapper[]
/**
 * Maps the user an external provider described onto the user the rest of the server sees: the principal of the
 * session, whose name is the local account's username (so it is the {@code sub} of the issued tokens, as it is for
 * every other way of signing in), whose authorities are the account's own, and which still carries the claims of the
 * provider (the {@code amr} among them).
 *
 * <p>The principal is stored with the authorization and read back at the token request through a polymorphic
 * allow-list, so every claim is normalised to a JSON-friendly value first: lists are mutable lists (an immutable one
 * is not on the allow-list), instants are epoch seconds and URLs are strings.
 */
@Component
public class FederatedUserMapper {

    /** Name of the attribute that holds the username of the local account. */
    public static final String LOCAL_USERNAME_ATTRIBUTE = "local_username";

    /** Claim of the upstream authentication methods (RFC 8176). */
    public static final String AMR_CLAIM = "amr";

    /** Claim that says that the provider verified the e-mail address (the standard OIDC one). */
    static final String EMAIL_VERIFIED_CLAIM = "email_verified";

    /** Optional claim of Microsoft Entra ID that says that the owner of the e-mail domain verified the address. */
    static final String ENTRA_DOMAIN_VERIFIED_CLAIM = "xms_edov";

    /**
     * Maps an OpenID Connect user.
     *
     * @param upstream    the user the provider described.
     * @param username    username of the local account.
     * @param authorities authorities of the local account.
     * @return a user named after the account, with the claims of the provider.
     */
    public OidcUser toLocalUser(
            final OidcUser upstream, final String username, final Collection<? extends GrantedAuthority> authorities) {
        final var claims = safeClaims(upstream.getIdToken().getClaims());
        final var token = upstream.getIdToken();
        final var idToken = new OidcIdToken(token.getTokenValue(), token.getIssuedAt(), token.getExpiresAt(), claims);
        final var info = new LinkedHashMap<String, Object>();
        info.put(IdTokenClaimNames.SUB, upstream.getSubject());
        info.put(LOCAL_USERNAME_ATTRIBUTE, username);
        return new DefaultOidcUser(List.copyOf(authorities), idToken, new OidcUserInfo(info),
                LOCAL_USERNAME_ATTRIBUTE);
    }

    /**
     * Maps an OAuth 2.0 user. Only the attributes in {@code kept} are carried over (the profile of such a provider may
     * hold nested objects that have no business in the session).
     *
     * @param upstream    the user the provider described.
     * @param kept        names of the attributes to keep.
     * @param email       verified e-mail address, or {@code null}; it replaces the provider's {@code email}.
     * @param username    username of the local account.
     * @param authorities authorities of the local account.
     * @return a user named after the account.
     */
    public OAuth2User toLocalUser(final OAuth2User upstream, final Collection<String> kept, final String email,
            final String username, final Collection<? extends GrantedAuthority> authorities) {
        final var attributes = new LinkedHashMap<String, Object>();
        upstream.getAttributes().forEach((name, value) -> {
            if (kept.contains(name) && value != null) {
                attributes.put(name, safe(value));
            }
        });
        attributes.remove("email");
        if (email != null) {
            attributes.put("email", email);
        }
        attributes.put(LOCAL_USERNAME_ATTRIBUTE, username);
        return new DefaultOAuth2User(List.copyOf(authorities), attributes, LOCAL_USERNAME_ATTRIBUTE);
    }

    /**
     * Tells whether the provider vouches for the e-mail address of an OpenID Connect user. The standard
     * {@code email_verified} claim does (a string {@code "true"} too, as Apple sends it); Microsoft Entra ID has no
     * such claim in its default tokens, so its optional {@code xms_edov} claim counts, and without either the address
     * is not verified: Entra's {@code email} can be set by a tenant administrator to any value.
     *
     * @param user the user the provider described.
     * @return {@code true} when the address is verified.
     */
    public boolean emailVerified(final OidcUser user) {
        return Boolean.TRUE.equals(user.getEmailVerified())
                || Boolean.TRUE.equals(user.getClaimAsBoolean(ENTRA_DOMAIN_VERIFIED_CLAIM));
    }

    /**
     * Reads the {@code amr} values the provider reported.
     *
     * @param user the user, as mapped by this class or as the provider described it.
     * @return the values, as strings; empty when there is none.
     */
    public List<String> upstreamAmr(final OAuth2User user) {
        final var amr = user.getAttribute(AMR_CLAIM);
        if (amr instanceof final Collection<?> values) {
            return values.stream().filter(Objects::nonNull).map(Object::toString).toList();
        }
        return List.of();
    }

    /**
     * Normalises a claim map.
     *
     * @param claims the claims.
     * @return a new, mutable map of JSON-friendly values.
     */
    private Map<String, Object> safeClaims(final Map<String, Object> claims) {
        final var result = new LinkedHashMap<String, Object>();
        claims.forEach((name, value) -> {
            if (value != null) {
                result.put(name, safe(value));
            }
        });
        return result;
    }

    /**
     * Normalises a value.
     *
     * @param value the value.
     * @return a JSON-friendly equivalent.
     */
    private Object safe(final Object value) {
        return switch (value) {
            case final Instant instant -> instant.getEpochSecond();
            case final URL url -> url.toString();
            case final Collection<?> collection -> collection.stream().filter(Objects::nonNull)
                    .map(this::safe).collect(Collectors.toCollection(ArrayList::new));
            case final Map<?, ?> map -> {
                final var copy = new LinkedHashMap<String, Object>();
                map.forEach((key, entry) -> {
                    if (entry != null) {
                        copy.put(String.valueOf(key), safe(entry));
                    }
                });
                yield copy;
            }
            default -> value;
        };
    }
}
// end::social-user-mapper[]
