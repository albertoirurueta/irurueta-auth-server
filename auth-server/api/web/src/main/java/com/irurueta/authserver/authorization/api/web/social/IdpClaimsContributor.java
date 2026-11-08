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

import com.irurueta.authserver.authorization.api.web.tokens.JwtClaimsContributor;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.stereotype.Component;

// tag::social-claims[]
/**
 * Adds to the tokens of a user who signed in with an external provider the claim {@code idp} (the registration id of
 * the provider). The {@code sub} is the local account's username, because the principal's name is (see
 * {@link FederatedUserMapper}), so a token of a federated sign-in is indistinguishable from any other in what it says
 * about the user.
 *
 * <p>When the provider is trusted for its multi-factor authentication and proved it (the strong factor,
 * {@link FederatedFactor#STRONG_AUTHORITY}), the upstream {@code amr} values are added to the {@code amr} claim the
 * {@link com.irurueta.authserver.authorization.api.web.mfa.MfaClaimsContributor} wrote (each value once, so the
 * repeated ones of the factor and of the provider are listed once, and {@code mfa} is there exactly once). The
 * {@code acr} is not set here: the strong factor is {@link
 * com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor#multiFactor() multi-factor alone}, so the
 * multi-factor contributor already wrote the multi-factor class, from the same rule the step-up checks use. The
 * upstream {@code amr} of a provider that is not trusted is never copied: it would claim a strength the server did not
 * accept.
 */
@Component
@Order(IdpClaimsContributor.ORDER)
@RequiredArgsConstructor
public class IdpClaimsContributor implements JwtClaimsContributor {

    /** Order of the contributor: after the multi-factor one, whose {@code amr} it extends. */
    public static final int ORDER = 110;

    /** Name of the claim that says which provider authenticated the user. */
    public static final String IDP_CLAIM = "idp";

    /** Reads the upstream {@code amr}. */
    private final FederatedUserMapper userMapper;

    /**
     * Adds the claims.
     *
     * @param context the token context.
     * @param claims  the claims, which this method extends.
     */
    @Override
    public void contribute(final OAuth2TokenContext context, final Map<String, Object> claims) {
        if (!(context.getPrincipal() instanceof final OAuth2AuthenticationToken token)) {
            return;
        }
        claims.put(IDP_CLAIM, token.getAuthorizedClientRegistrationId());
        final var strong = token.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .anyMatch(FederatedFactor.STRONG_AUTHORITY::equals);
        if (!strong) {
            return;
        }
        // a mutable list on purpose: the authorization store only deserializes allow-listed types
        final var amr = new ArrayList<String>(existingAmr(claims));
        final var upstream = userMapper.upstreamAmr(Objects.requireNonNull(token.getPrincipal()));
        upstream.stream().filter(value -> !amr.contains(value)).forEach(amr::add);
        claims.put(IdTokenClaimNames.AMR, amr);
    }

    /**
     * Reads the {@code amr} already in the claims.
     *
     * @param claims the claims.
     * @return its values; empty when there is none.
     */
    private static List<String> existingAmr(final Map<String, Object> claims) {
        return claims.get(IdTokenClaimNames.AMR) instanceof final List<?> values
                ? values.stream().map(String::valueOf).distinct().toList() : List.of();
    }
}
// end::social-claims[]
