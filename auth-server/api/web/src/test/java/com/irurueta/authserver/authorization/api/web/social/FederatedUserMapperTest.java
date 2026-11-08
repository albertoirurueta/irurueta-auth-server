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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

/**
 * Unit tests of {@link FederatedUserMapper}.
 */
class FederatedUserMapperTest {

    /** Local username of the tests. */
    private static final String USERNAME = "alice";

    /** Subject the provider assigned. */
    private static final String SUBJECT = "provider-subject";

    /** Issue instant of the test tokens. */
    private static final Instant ISSUED = Instant.parse("2026-01-01T10:00:00Z");

    /** Lifetime of the test tokens, in seconds. */
    private static final long LIFETIME_SECONDS = 600L;

    /** Mapper under test. */
    private final FederatedUserMapper mapper = new FederatedUserMapper();

    /**
     * Verifies that the principal is named after the local account, has the account's authorities and keeps the claims
     * of the provider, normalised to values the authorization store can read back.
     *
     * @throws MalformedURLException if the test issuer is not a URL.
     */
    @Test
    void toLocalUserOidc_whenUpstreamHasClaims_namesTheUserAfterTheAccountAndNormalisesTheClaims()
            throws MalformedURLException {
        final var claims = new LinkedHashMap<String, Object>();
        claims.put("sub", SUBJECT);
        claims.put("iss", URI.create("https://issuer.example").toURL());
        claims.put("aud", List.of("client"));
        claims.put("amr", List.of("pwd", "mfa"));
        claims.put("iat", ISSUED);
        claims.put("nested", Map.of("a", List.of("b")));
        final var upstream = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")),
                new OidcIdToken("token", ISSUED, ISSUED.plusSeconds(LIFETIME_SECONDS), claims));

        final var user = mapper.toLocalUser(upstream, USERNAME, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertEquals(USERNAME, user.getName());
        assertEquals(SUBJECT, user.getSubject());
        assertEquals(List.of("ROLE_USER"), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        assertEquals("https://issuer.example", user.getIdToken().getClaims().get("iss"));
        assertEquals(ISSUED.getEpochSecond(), user.getIdToken().getClaims().get("iat"));
        assertInstanceOf(ArrayList.class, user.getIdToken().getClaims().get("aud"));
        assertInstanceOf(ArrayList.class, user.getIdToken().getClaims().get("amr"));
        assertEquals(List.of("pwd", "mfa"), mapper.upstreamAmr(user));
        assertEquals(USERNAME, user.getAttribute(FederatedUserMapper.LOCAL_USERNAME_ATTRIBUTE));
        assertInstanceOf(LinkedHashMap.class, user.getIdToken().getClaims().get("nested"));
    }

    /**
     * Verifies that only the attributes asked for are kept of an OAuth 2.0 user, the e-mail address being the
     * verified one and never the provider's.
     */
    @Test
    void toLocalUserOAuth2_whenUpstreamHasAttributes_keepsOnlyTheAskedOnesAndTheVerifiedEmail() {
        final var attributes = new LinkedHashMap<String, Object>();
        attributes.put("id", 1L);
        attributes.put("login", "octo");
        attributes.put("email", "unverified@example.org");
        attributes.put("plan", Map.of("name", "free"));
        attributes.put("name", null);
        final var upstream = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("OAUTH2_USER")), attributes,
                "id");

        final var user = mapper.toLocalUser(upstream, List.of("id", "login", "name"), "verified@example.org",
                USERNAME, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertEquals(USERNAME, user.getName());
        assertEquals(1L, (long) user.<Long>getAttribute("id"));
        assertEquals("octo", user.getAttribute("login"));
        assertEquals("verified@example.org", user.getAttribute("email"));
        assertNull(user.getAttribute("plan"));
        assertFalse(user.getAttributes().containsKey("name"));
    }

    /**
     * Verifies that an OAuth 2.0 user without a verified address has no e-mail attribute at all.
     */
    @Test
    void toLocalUserOAuth2_whenThereIsNoVerifiedEmail_hasNoEmailAttribute() {
        final var upstream = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("OAUTH2_USER")),
                Map.of("id", 1L, "email", "unverified@example.org"), "id");

        final var user = mapper.toLocalUser(upstream, List.of("id"), null, USERNAME, List.of());

        assertFalse(user.getAttributes().containsKey("email"));
    }

    /**
     * Verifies which claims make an address verified: the standard one (as a boolean or as Apple's string) and Entra's
     * optional domain-verified one, and nothing else.
     */
    @Test
    void emailVerified_whenAsked_acceptsTheStandardClaimAndEntraDomainVerified() {
        assertTrue(mapper.emailVerified(user(Map.of("email_verified", true))));
        assertTrue(mapper.emailVerified(user(Map.of("email_verified", "true"))));
        assertTrue(mapper.emailVerified(user(Map.of("xms_edov", true))));
        assertFalse(mapper.emailVerified(user(Map.of("email_verified", false))));
        assertFalse(mapper.emailVerified(user(Map.of())));
    }

    /**
     * Verifies that the upstream methods are read as strings, and none is reported when the claim is not a list.
     */
    @Test
    void upstreamAmr_whenClaimIsNotAList_isEmpty() {
        assertEquals(List.of("pwd", "1"), mapper.upstreamAmr(user(Map.of("amr", List.of("pwd", 1)))));
        assertTrue(mapper.upstreamAmr(user(Map.of("amr", "mfa"))).isEmpty());
        assertTrue(mapper.upstreamAmr(user(Map.of())).isEmpty());
    }

    /**
     * Builds an OpenID Connect user with some extra claims.
     *
     * @param extra the claims besides the subject.
     * @return the user.
     */
    private static DefaultOidcUser user(final Map<String, Object> extra) {
        final var claims = new LinkedHashMap<String, Object>(extra);
        claims.put("sub", SUBJECT);
        return new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")),
                new OidcIdToken("token", ISSUED, ISSUED.plusSeconds(LIFETIME_SECONDS), claims),
                new OidcUserInfo(Map.of("sub", SUBJECT)));
    }
}
