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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.application.ott.OttVerificationResult;
import com.irurueta.authserver.authorization.application.ott.VerifyOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/** Unit tests of {@link OttCodeAuthenticationProvider}. */
@ExtendWith(MockitoExtension.class)
class OttCodeAuthenticationProviderTest {

    /** The code. */
    private static final String CODE = "123456";

    /** Verifies the code. */
    @Mock
    private VerifyOneTimeCodeUseCase verifyOneTimeCodeUseCase;

    /** Loads the account. */
    @Mock
    private UserDetailsService userDetailsService;

    /** Real grantor over a fixed clock. */
    @Spy
    private FactorGrantor factorGrantor = new FactorGrantor(Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));

    /** Provider under test. */
    @InjectMocks
    private OttCodeAuthenticationProvider provider;

    /** A correct e-mail code signs the user in with the e-mail factor. */
    @Test
    void authenticate_whenAnEmailCodeIsCorrect_grantsTheEmailFactor() {
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.LOGIN))
                .thenReturn(OttVerificationResult.success(OttChannel.EMAIL));
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(user());

        final var result = provider.authenticate(new OttCodeAuthenticationToken("alice", CODE, "binding"));

        assertInstanceOf(OneTimeTokenAuthentication.class, result);
        assertTrue(result.isAuthenticated());
        assertEquals(Set.of("ROLE_USER", "FACTOR_OTT"), authorities(result.getAuthorities()));
    }

    /** A correct SMS code signs the user in with the SMS factor. */
    @Test
    void authenticate_whenAnSmsCodeIsCorrect_grantsTheSmsFactor() {
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.LOGIN))
                .thenReturn(OttVerificationResult.success(OttChannel.SMS));
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(user());

        final var result = provider.authenticate(new OttCodeAuthenticationToken("alice", CODE, "binding"));

        assertEquals(Set.of("ROLE_USER", "FACTOR_OTT_SMS"), authorities(result.getAuthorities()));
    }

    /** A wrong code is refused, and the account is not even looked at. */
    @Test
    void authenticate_whenTheCodeIsWrong_throwsBadCredentialsException() {
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.LOGIN))
                .thenReturn(OttVerificationResult.failure());
        final var request = new OttCodeAuthenticationToken("alice", CODE, "binding");

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
        verifyNoInteractions(userDetailsService);
    }

    /** A locked second factor is refused as locked. */
    @Test
    void authenticate_whenTheUseCaseReportsLocked_throwsLockedException() {
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.LOGIN))
                .thenReturn(OttVerificationResult.locked());
        final var request = new OttCodeAuthenticationToken("alice", CODE, "binding");

        assertThrows(LockedException.class, () -> provider.authenticate(request));
    }

    /** An account that vanished is refused like a wrong code. */
    @Test
    void authenticate_whenTheAccountIsGone_throwsBadCredentialsException() {
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.LOGIN))
                .thenReturn(OttVerificationResult.success(OttChannel.EMAIL));
        when(userDetailsService.loadUserByUsername("alice")).thenThrow(new UsernameNotFoundException("alice"));
        final var request = new OttCodeAuthenticationToken("alice", CODE, "binding");

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
    }

    /** An account that cannot sign in is refused as the user service says. */
    @Test
    void authenticate_whenTheAccountIsDisabled_propagatesTheRefusal() {
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.LOGIN))
                .thenReturn(OttVerificationResult.success(OttChannel.EMAIL));
        when(userDetailsService.loadUserByUsername("alice")).thenThrow(new DisabledException("disabled"));
        final var request = new OttCodeAuthenticationToken("alice", CODE, "binding");

        assertThrows(DisabledException.class, () -> provider.authenticate(request));
    }

    /** Only code requests are supported. */
    @Test
    void supports_whenGivenARequestType_isTrueForCodeRequestsOnly() {
        assertTrue(provider.supports(OttCodeAuthenticationToken.class));
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
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
     * Lists authorities by name.
     *
     * @param authorities the authorities.
     * @return their names.
     */
    private static Set<String> authorities(final Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
    }
}
