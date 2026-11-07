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
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.application.ott.OttVerificationResult;
import com.irurueta.authserver.authorization.application.ott.VerifyOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/** Unit tests of {@link OttSecondFactorAuthenticationProvider}. */
@ExtendWith(MockitoExtension.class)
class OttSecondFactorAuthenticationProviderTest {

    /** The code. */
    private static final String CODE = "123456";

    /** Every channel. */
    private static final Set<OttChannel> ALL = EnumSet.allOf(OttChannel.class);

    /** Verifies the code. */
    @Mock
    private VerifyOneTimeCodeUseCase verifyOneTimeCodeUseCase;

    /** Decides which channels may be the second factor. */
    @Mock
    private OttSecondFactorChannels secondFactorChannels;

    /** Provider under test. */
    private OttSecondFactorAuthenticationProvider provider;

    /** Creates the provider over a real grantor. */
    @BeforeEach
    void setUp() {
        provider = new OttSecondFactorAuthenticationProvider(verifyOneTimeCodeUseCase,
                new FactorGrantor(Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)), secondFactorChannels);
    }

    /** A correct e-mail code adds the e-mail second factor to what the user holds. */
    @Test
    void authenticate_whenAnEmailCodeIsCorrect_addsTheEmailSecondFactor() {
        final var primary = primary("FACTOR_PASSWORD");
        when(secondFactorChannels.allowed(primary)).thenReturn(ALL);
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.SECOND_FACTOR, ALL))
                .thenReturn(OttVerificationResult.success(OttChannel.EMAIL));

        final var result = provider.authenticate(new OttSecondFactorToken(primary, CODE, "binding"));

        assertEquals(Set.of("FACTOR_PASSWORD", "FACTOR_OTT_EMAIL_2FA"), authorities(result));
    }

    /** A correct SMS code adds the SMS second factor. */
    @Test
    void authenticate_whenAnSmsCodeIsCorrect_addsTheSmsSecondFactor() {
        final var primary = primary("FACTOR_PASSWORD");
        when(secondFactorChannels.allowed(primary)).thenReturn(ALL);
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.SECOND_FACTOR, ALL))
                .thenReturn(OttVerificationResult.success(OttChannel.SMS));

        final var result = provider.authenticate(new OttSecondFactorToken(primary, CODE, "binding"));

        assertEquals(Set.of("FACTOR_PASSWORD", "FACTOR_OTT_SMS_2FA"), authorities(result));
    }

    /** A wrong code is refused. */
    @Test
    void authenticate_whenTheCodeIsWrong_throwsBadCredentialsException() {
        final var primary = primary("FACTOR_PASSWORD");
        when(secondFactorChannels.allowed(primary)).thenReturn(ALL);
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.SECOND_FACTOR, ALL))
                .thenReturn(OttVerificationResult.failure());
        final var request = new OttSecondFactorToken(primary, CODE, "binding");

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
    }

    /** A locked second factor is refused as locked, even for a correct code. */
    @Test
    void authenticate_whenTheSecondFactorIsLocked_throwsLockedException() {
        final var primary = primary("FACTOR_PASSWORD");
        when(secondFactorChannels.allowed(primary)).thenReturn(ALL);
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.SECOND_FACTOR, ALL))
                .thenReturn(OttVerificationResult.locked());
        final var request = new OttSecondFactorToken(primary, CODE, "binding");

        assertThrows(LockedException.class, () -> provider.authenticate(request));
    }

    /**
     * Only the allowed channels are handed to the verification, before the code is compared: a code of another channel
     * (here the e-mail that signed the user in) is a failure counted by the use case, and refused.
     */
    @Test
    void authenticate_whenTheChannelIsNotAllowed_passesTheAllowedChannelsAndThrowsBadCredentialsException() {
        final var primary = primary("FACTOR_OTT");
        final var allowed = EnumSet.of(OttChannel.SMS);
        when(secondFactorChannels.allowed(primary)).thenReturn(allowed);
        when(verifyOneTimeCodeUseCase.execute("binding", "alice", CODE, OttPurpose.SECOND_FACTOR, allowed))
                .thenReturn(OttVerificationResult.failure());
        final var request = new OttSecondFactorToken(primary, CODE, "binding");

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
    }

    /** Only second-factor requests are supported. */
    @Test
    void supports_whenGivenARequestType_isTrueForSecondFactorRequestsOnly() {
        assertTrue(provider.supports(OttSecondFactorToken.class));
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    /**
     * Builds the authentication the user already holds.
     *
     * @param factor the factor authority it holds.
     * @return the authentication.
     */
    private static Authentication primary(final String factor) {
        return UsernamePasswordAuthenticationToken.authenticated("alice", "x",
                List.of(FactorGrantedAuthority.fromAuthority(factor)));
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
