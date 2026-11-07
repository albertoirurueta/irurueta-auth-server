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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.tokens.IssuedTokenClaims;
import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

/**
 * Unit tests of {@link MfaClaimsContributor}, including its application through {@link IssuedTokenClaims} to a real
 * {@link OAuth2TokenClaimsContext}.
 */
class MfaClaimsContributorTest {

    /** Authority of the password factor. */
    private static final String PASSWORD_AUTHORITY = FactorGrantedAuthority.PASSWORD_AUTHORITY;

    /** Authority of the TOTP factor. */
    private static final String TOTP_AUTHORITY = "FACTOR_TOTP";

    /** Authority of the trusted-device factor. */
    private static final String TRUSTED_DEVICE_AUTHORITY = "FACTOR_TRUSTED_DEVICE";

    /** Authority of the e-mail one-time token as a sign-in. */
    private static final String OTT_EMAIL_AUTHORITY = "FACTOR_OTT";

    /** Authority of the e-mail one-time token as a second factor. */
    private static final String OTT_EMAIL_SECOND_AUTHORITY = "FACTOR_OTT_EMAIL_2FA";

    /** Authority of the SMS one-time token as a second factor. */
    private static final String OTT_SMS_SECOND_AUTHORITY = "FACTOR_OTT_SMS_2FA";

    /** Authority of a factor nobody registered. */
    private static final String UNKNOWN_AUTHORITY = "FACTOR_UNKNOWN";

    /** Name of the test user. */
    private static final String USERNAME = "alice";

    /** Instant the password was presented. */
    private static final Instant PASSWORD_TIME = Instant.parse("2026-01-01T10:00:00Z");

    /** Instant the second factor was presented. */
    private static final Instant TOTP_TIME = Instant.parse("2026-01-01T10:01:00Z");

    /** Subject under test. */
    private MfaClaimsContributor contributor;

    /**
     * Creates the subject over a real timeline of a registry with a password, a TOTP and a trusted-device factor.
     */
    @BeforeEach
    void setUp() {
        final var registry = new AuthenticationFactorRegistry(List.of(
                new AuthenticationFactor("password", "pwd", PASSWORD_AUTHORITY, FactorStrength.PRIMARY),
                new AuthenticationFactor("totp", "otp", TOTP_AUTHORITY, FactorStrength.SECOND),
                new AuthenticationFactor("trusted-device", "trusted-device", TRUSTED_DEVICE_AUTHORITY,
                        FactorStrength.REMEMBERED)));
        contributor = new MfaClaimsContributor(new FactorTimeline(registry, new MfaPolicy()));
    }

    /**
     * A password-only authentication gets amr pwd, the password acr and the instant of the password.
     */
    @Test
    void contribute_whenOnlyPasswordPresented_addsPasswordClaims() {
        final var claims = new HashMap<String, Object>();

        contributor.contribute(contextOf(authentication(factor(PASSWORD_AUTHORITY, PASSWORD_TIME))), claims);

        assertEquals(List.of("pwd"), claims.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.PASSWORD, claims.get(IdTokenClaimNames.ACR));
        assertEquals(PASSWORD_TIME.getEpochSecond(), claims.get(IdTokenClaimNames.AUTH_TIME));
    }

    /**
     * Two factors give both amr values in presentation order, mfa, the multi-factor acr and the instant of the
     * password, not of the later second factor.
     */
    @Test
    void contribute_whenTwoFactorsPresented_addsMultiFactorClaims() {
        final var claims = new HashMap<String, Object>();
        final var principal = authentication(factor(TOTP_AUTHORITY, TOTP_TIME),
                factor(PASSWORD_AUTHORITY, PASSWORD_TIME));

        contributor.contribute(contextOf(principal), claims);

        assertEquals(List.of("pwd", "otp", "mfa"), claims.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, claims.get(IdTokenClaimNames.ACR));
        assertEquals(PASSWORD_TIME.getEpochSecond(), claims.get(IdTokenClaimNames.AUTH_TIME));
    }

    /**
     * A trusted device that skipped the second factor is not reported: the claims are those of the password alone.
     */
    @Test
    void contribute_whenTrustedDeviceSkippedTheSecondFactor_addsPasswordClaims() {
        final var claims = new HashMap<String, Object>();
        final var principal = authentication(factor(PASSWORD_AUTHORITY, PASSWORD_TIME),
                factor(TRUSTED_DEVICE_AUTHORITY, TOTP_TIME));

        contributor.contribute(contextOf(principal), claims);

        assertEquals(List.of("pwd"), claims.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.PASSWORD, claims.get(IdTokenClaimNames.ACR));
        assertEquals(PASSWORD_TIME.getEpochSecond(), claims.get(IdTokenClaimNames.AUTH_TIME));
    }

    /**
     * Authorities that are not factors, or of an unregistered factor, are ignored.
     */
    @Test
    void contribute_whenAuthoritiesAreNotRegisteredFactors_ignoresThem() {
        final var claims = new HashMap<String, Object>();
        final var principal = authentication(new SimpleGrantedAuthority("ROLE_USER"),
                factor(UNKNOWN_AUTHORITY, TOTP_TIME), factor(PASSWORD_AUTHORITY, PASSWORD_TIME));

        contributor.contribute(contextOf(principal), claims);

        assertEquals(List.of("pwd"), claims.get(IdTokenClaimNames.AMR));
    }

    /**
     * A principal with no factor, as in the client credentials grant, gets no claim.
     */
    @Test
    void contribute_whenNoFactorPresented_addsNothing() {
        final var claims = new HashMap<String, Object>();

        contributor.contribute(contextOf(authentication(new SimpleGrantedAuthority("ROLE_USER"))), claims);

        assertTrue(claims.isEmpty());
    }

    /**
     * A context without principal gets no claim.
     */
    @Test
    void contribute_whenContextHasNoPrincipal_addsNothing() {
        final var claims = new HashMap<String, Object>();

        contributor.contribute(mock(OAuth2TokenContext.class), claims);

        assertTrue(claims.isEmpty());
    }

    /**
     * Applied through {@link IssuedTokenClaims} to a real token claims context, the contributor adds its claims to
     * the access token, with a mutable amr list.
     */
    @Test
    void contribute_whenAppliedThroughIssuedTokenClaims_addsClaimsToTheAccessToken() {
        final var issuedTokenClaims = new IssuedTokenClaims(mock(FindUserAccountUseCase.class),
                List.of(contributor));
        final var client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback").build();
        final var context = OAuth2TokenClaimsContext.with(OAuth2TokenClaimsSet.builder().subject(USERNAME))
                .registeredClient(client)
                .principal(authentication(factor(PASSWORD_AUTHORITY, PASSWORD_TIME),
                        factor(TOTP_AUTHORITY, TOTP_TIME)))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN).build();

        context.getClaims().claims(claims -> issuedTokenClaims.apply(context, claims));

        final var built = context.getClaims().build().getClaims();
        assertEquals(List.of("pwd", "otp", "mfa"), built.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, built.get(IdTokenClaimNames.ACR));
        assertEquals(PASSWORD_TIME.getEpochSecond(), built.get(IdTokenClaimNames.AUTH_TIME));
        assertFalse(built.containsKey(IssuedTokenClaims.TENANT_CLAIM));
    }

    /**
     * ID tokens get no auth_time from the contributor, because the framework sets it itself.
     */
    @Test
    void contribute_whenTokenIsAnIdToken_doesNotAddAuthTime() {
        final var claims = new HashMap<String, Object>();
        final var context = mock(OAuth2TokenContext.class);
        when(context.getPrincipal()).thenReturn(authentication(factor(PASSWORD_AUTHORITY, PASSWORD_TIME)));
        when(context.getTokenType()).thenReturn(new OAuth2TokenType(OidcParameterNames.ID_TOKEN));

        contributor.contribute(context, claims);

        assertEquals(List.of("pwd"), claims.get(IdTokenClaimNames.AMR));
        assertFalse(claims.containsKey(IdTokenClaimNames.AUTH_TIME));
    }

    /**
     * A password followed by an e-mail code and a TOTP code presents {@code otp} twice (two different factors with the
     * same RFC 8176 value): it is listed once, and {@code mfa} is still added.
     */
    @Test
    void contribute_whenTwoSecondFactorsShareTheOtpValue_listsItOnceAndAddsMfa() {
        final var claims = new HashMap<String, Object>();
        final var contributorWithOtt = contributorWithOneTimeTokenFactors();
        final var principal = authentication(factor(OTT_EMAIL_SECOND_AUTHORITY, TOTP_TIME),
                factor(TOTP_AUTHORITY, TOTP_TIME), factor(PASSWORD_AUTHORITY, PASSWORD_TIME));

        contributorWithOtt.contribute(contextOf(principal), claims);

        assertEquals(List.of("pwd", "otp", "mfa"), claims.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, claims.get(IdTokenClaimNames.ACR));
    }

    /**
     * A password followed by an e-mail code (second factor) is multi-factor and reports {@code otp}; with an SMS code
     * it reports {@code sms}; and a sign-in by e-mail code alone is a single factor.
     */
    @Test
    void contribute_whenOneTimeTokenFactorsArePresented_reportsTheirAmrValues() {
        final var contributorWithOtt = contributorWithOneTimeTokenFactors();
        final var email = new HashMap<String, Object>();
        final var sms = new HashMap<String, Object>();
        final var alone = new HashMap<String, Object>();

        contributorWithOtt.contribute(contextOf(authentication(factor(OTT_EMAIL_SECOND_AUTHORITY, TOTP_TIME),
                factor(PASSWORD_AUTHORITY, PASSWORD_TIME))), email);
        contributorWithOtt.contribute(contextOf(authentication(factor(OTT_SMS_SECOND_AUTHORITY, TOTP_TIME),
                factor(PASSWORD_AUTHORITY, PASSWORD_TIME))), sms);
        contributorWithOtt.contribute(contextOf(authentication(factor(OTT_EMAIL_AUTHORITY, PASSWORD_TIME))), alone);

        assertEquals(List.of("pwd", "otp", "mfa"), email.get(IdTokenClaimNames.AMR));
        assertEquals(List.of("pwd", "sms", "mfa"), sms.get(IdTokenClaimNames.AMR));
        assertEquals(List.of("otp"), alone.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.PASSWORD, alone.get(IdTokenClaimNames.ACR));
    }

    /**
     * The contributor is ordered after the built-in claims.
     */
    @Test
    void order_whenReadFromAnnotation_isTheDeclaredOrder() {
        assertEquals(MfaClaimsContributor.ORDER, MfaClaimsContributor.class.getAnnotation(Order.class).value());
    }

    /**
     * Builds a contributor over a registry that also holds the four one-time token factors, as the application's
     * registry does.
     *
     * @return the contributor.
     */
    private static MfaClaimsContributor contributorWithOneTimeTokenFactors() {
        final var registry = new AuthenticationFactorRegistry(List.of(
                new AuthenticationFactor("password", "pwd", PASSWORD_AUTHORITY, FactorStrength.PRIMARY),
                new AuthenticationFactor("totp", "otp", TOTP_AUTHORITY, FactorStrength.SECOND),
                new AuthenticationFactor("ott-email", "otp", OTT_EMAIL_AUTHORITY, FactorStrength.PRIMARY),
                new AuthenticationFactor("ott-email-2fa", "otp", OTT_EMAIL_SECOND_AUTHORITY, FactorStrength.SECOND),
                new AuthenticationFactor("ott-sms-2fa", "sms", OTT_SMS_SECOND_AUTHORITY, FactorStrength.SECOND)));
        return new MfaClaimsContributor(new FactorTimeline(registry, new MfaPolicy()));
    }

    /**
     * Builds a context whose principal is the authentication.
     *
     * @param principal the authentication.
     * @return the mocked context.
     */
    private static OAuth2TokenContext contextOf(final Authentication principal) {
        final var context = mock(OAuth2TokenContext.class);
        when(context.getPrincipal()).thenReturn(principal);
        lenient().when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        return context;
    }

    /**
     * Builds an authentication with authorities.
     *
     * @param authorities the authorities.
     * @return the authentication.
     */
    private static Authentication authentication(final GrantedAuthority... authorities) {
        return new TestingAuthenticationToken(USERNAME, null, List.of(authorities));
    }

    /**
     * Builds a factor authority.
     *
     * @param authority the authority.
     * @param issuedAt  the instant it was granted.
     * @return the factor authority.
     */
    private static FactorGrantedAuthority factor(final String authority, final Instant issuedAt) {
        return FactorGrantedAuthority.withAuthority(authority).issuedAt(issuedAt).build();
    }
}
