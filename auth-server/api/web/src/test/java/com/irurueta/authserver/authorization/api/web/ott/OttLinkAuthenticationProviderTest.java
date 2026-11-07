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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.AuthenticationFactorRegistry;
import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/** Unit tests of {@link OttLinkAuthenticationProvider}. */
@ExtendWith(MockitoExtension.class)
class OttLinkAuthenticationProviderTest {

    /** The token of a link. */
    private static final String TOKEN = "7b7ea0e1-1b0f-4f55-8a54-2a1f3f0a1b2c";

    /** Store of the link tokens. */
    @Mock
    private OneTimeTokenService oneTimeTokenService;

    /** Loads the account. */
    @Mock
    private UserDetailsService userDetailsService;

    /** Decides which channels may be the second factor. */
    @Mock
    private OttSecondFactorChannels secondFactorChannels;

    /** Provider under test. */
    private OttLinkAuthenticationProvider provider;

    /** Creates the provider over a real grantor and rules. */
    @BeforeEach
    void setUp() {
        final var registry = new AuthenticationFactorRegistry(List.of(
                new AuthenticationFactor("password", "pwd", "FACTOR_PASSWORD", FactorStrength.PRIMARY),
                new AuthenticationFactor("ott-email", "otp", "FACTOR_OTT", FactorStrength.PRIMARY),
                new AuthenticationFactor("totp", "otp", "FACTOR_TOTP", FactorStrength.SECOND)));
        provider = new OttLinkAuthenticationProvider(oneTimeTokenService, userDetailsService,
                new FactorGrantor(Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)), new PrimaryFactorSession(registry),
                secondFactorChannels);
    }

    /** Clears the security context. */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /** A sign-in link signs the user in with the e-mail factor. */
    @Test
    void authenticate_whenASignInLinkIsConfirmed_grantsTheEmailFactor() {
        consumes("alice");
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(user());

        final var result = provider.authenticate(new OneTimeTokenAuthenticationToken(TOKEN));

        assertTrue(result.isAuthenticated());
        assertEquals(Set.of("ROLE_USER", "FACTOR_OTT"), authorities(result));
    }

    /** A second-factor link confirmed in the signed-in session of its user adds the second factor. */
    @Test
    void authenticate_whenASecondFactorLinkIsConfirmedInTheSessionOfItsUser_grantsTheSecondFactor() {
        consumes(LinkTokenUsername.forLink("alice", true));
        signedIn("alice", "FACTOR_PASSWORD");
        when(secondFactorChannels.isAllowed(SecurityContextHolder.getContext().getAuthentication(),
                OttChannel.EMAIL)).thenReturn(true);
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(user());

        final var result = provider.authenticate(new OneTimeTokenAuthenticationToken(TOKEN));

        assertEquals(Set.of("ROLE_USER", "FACTOR_OTT_EMAIL_2FA"), authorities(result));
    }

    /** A second-factor link is refused in a browser that holds no session. */
    @Test
    void authenticate_whenASecondFactorLinkIsConfirmedWithoutSession_throwsBadCredentialsException() {
        consumes(LinkTokenUsername.forLink("alice", true));
        final var request = new OneTimeTokenAuthenticationToken(TOKEN);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
        verifyNoInteractions(userDetailsService);
    }

    /** A second-factor link is refused in the session of another user. */
    @Test
    void authenticate_whenASecondFactorLinkIsConfirmedInAnotherUsersSession_throwsBadCredentialsException() {
        consumes(LinkTokenUsername.forLink("alice", true));
        signedIn("mallory", "FACTOR_PASSWORD");
        final var request = new OneTimeTokenAuthenticationToken(TOKEN);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
    }

    /** A second-factor link is refused in a session that only holds a second factor. */
    @Test
    void authenticate_whenTheSessionHoldsNoPrimaryFactor_throwsBadCredentialsException() {
        consumes(LinkTokenUsername.forLink("alice", true));
        signedIn("alice", "FACTOR_TOTP");
        final var request = new OneTimeTokenAuthenticationToken(TOKEN);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
    }

    /**
     * An e-mail link cannot be the second factor of a session the e-mail channel is not allowed for (a user who signed
     * in by e-mail, or who has another confirmed second factor), and the account is not even loaded.
     */
    @Test
    void authenticate_whenTheEmailChannelIsNotAllowed_throwsBadCredentialsException() {
        consumes(LinkTokenUsername.forLink("alice", true));
        signedIn("alice", "FACTOR_PASSWORD");
        when(secondFactorChannels.isAllowed(SecurityContextHolder.getContext().getAuthentication(),
                OttChannel.EMAIL)).thenReturn(false);
        final var request = new OneTimeTokenAuthenticationToken(TOKEN);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
        verifyNoInteractions(userDetailsService);
    }

    /** An unknown, used or expired token is refused. */
    @Test
    void authenticate_whenTheTokenIsNotValid_throwsInvalidOneTimeTokenException() {
        when(oneTimeTokenService.consume(any())).thenReturn(null);
        final var request = new OneTimeTokenAuthenticationToken(TOKEN);

        assertThrows(InvalidOneTimeTokenException.class, () -> provider.authenticate(request));
    }

    /** A link of an account that vanished is refused. */
    @Test
    void authenticate_whenTheAccountIsGone_throwsBadCredentialsException() {
        consumes("alice");
        when(userDetailsService.loadUserByUsername("alice")).thenThrow(new UsernameNotFoundException("alice"));
        final var request = new OneTimeTokenAuthenticationToken(TOKEN);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
    }

    /** Only one-time token requests are supported. */
    @Test
    void supports_whenGivenARequestType_isTrueForTokenRequestsOnly() {
        assertTrue(provider.supports(OneTimeTokenAuthenticationToken.class));
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    /**
     * Makes the store hand back a token of a stored user name.
     *
     * @param storedUsername the user name the token was stored with.
     */
    private void consumes(final String storedUsername) {
        when(oneTimeTokenService.consume(any())).thenReturn(new DefaultOneTimeToken(TOKEN, storedUsername,
                Instant.EPOCH.plusSeconds(1)));
    }

    /**
     * Signs a user in the security context, holding a factor.
     *
     * @param username the user.
     * @param factor   the factor authority.
     */
    private static void signedIn(final String username, final String factor) {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                username, "x", List.of(FactorGrantedAuthority.fromAuthority(factor))));
    }

    /**
     * Builds the account.
     *
     * @return the user details.
     */
    private static User user() {
        return new User("alice", "x", List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    /**
     * Lists the authorities of an authentication by name.
     *
     * @param authentication the authentication.
     * @return their names.
     */
    private static Set<String> authorities(final Authentication authentication) {
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }
}
