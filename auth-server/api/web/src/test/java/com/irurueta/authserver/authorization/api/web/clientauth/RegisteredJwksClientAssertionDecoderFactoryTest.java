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
package com.irurueta.authserver.authorization.api.web.clientauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

/** Unit tests of {@link RegisteredJwksClientAssertionDecoderFactory}, with keys generated at run time. */
@ExtendWith(MockitoExtension.class)
class RegisteredJwksClientAssertionDecoderFactoryTest {

    /** Issuer of the server, the audience of the assertions. */
    private static final String ISSUER = "https://issuer.example.com";

    /** Size of the generated RSA keys. */
    private static final int KEY_SIZE = 2048;

    /** Seconds the assertions live. */
    private static final long LIFETIME_SECONDS = 60L;

    /** Key the client registers. */
    private static RSAKey clientKey;

    /** Another key, unknown to the server. */
    private static RSAKey otherKey;

    /** Validator of the lifetime and replay. */
    @Mock
    private ReplayRejectingJwtValidator replayValidator;

    /** Factory under test. */
    private RegisteredJwksClientAssertionDecoderFactory factory;

    /**
     * Generates the keys.
     *
     * @throws JOSEException if a key cannot be generated.
     */
    @BeforeAll
    static void generateKeys() throws JOSEException {
        clientKey = new RSAKeyGenerator(KEY_SIZE).keyID("client-key").generate();
        otherKey = new RSAKeyGenerator(KEY_SIZE).keyID("other-key").generate();
    }

    /** Creates the factory and the server context the default validators read. */
    @BeforeEach
    void setUp() {
        factory = new RegisteredJwksClientAssertionDecoderFactory(replayValidator);
        final var context = mock(AuthorizationServerContext.class);
        lenient().when(context.getIssuer()).thenReturn(ISSUER);
        lenient().when(context.getAuthorizationServerSettings())
                .thenReturn(AuthorizationServerSettings.builder().issuer(ISSUER).build());
        AuthorizationServerContextHolder.setContext(context);
    }

    /** Clears the server context. */
    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
    }

    /** An assertion signed by a registered key decodes, and the replay validator is consulted. */
    @Test
    void createDecoder_whenClientHasRegisteredJwks_decodesAssertionSignedByARegisteredKey() throws Exception {
        when(replayValidator.validate(any())).thenReturn(OAuth2TokenValidatorResult.success());
        final var client = clientWithJwks(clientKey, SignatureAlgorithm.RS256);

        final var jwt = factory.createDecoder(client).decode(assertion(client, clientKey));

        assertEquals(client.getClientId(), jwt.getSubject());
        verify(replayValidator).validate(any());
    }

    /** A replayed assertion is refused. */
    @Test
    void createDecoder_whenReplayValidatorFails_refusesTheAssertion() throws Exception {
        when(replayValidator.validate(any())).thenReturn(OAuth2TokenValidatorResult.failure(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT)));
        final var client = clientWithJwks(clientKey, SignatureAlgorithm.RS256);
        final var decoder = factory.createDecoder(client);
        final var assertion = assertion(client, clientKey);

        assertThrows(JwtException.class, () -> decoder.decode(assertion));
    }

    /** An assertion signed by a key that is not registered is refused before the replay check. */
    @Test
    void createDecoder_whenAssertionIsSignedByAnotherKey_refusesTheAssertion() throws Exception {
        final var client = clientWithJwks(clientKey, SignatureAlgorithm.RS256);
        final var decoder = factory.createDecoder(client);
        final var assertion = assertion(client, otherKey);

        assertThrows(JwtException.class, () -> decoder.decode(assertion));
        verify(replayValidator, never()).validate(any());
    }

    /** The decoder of an unchanged client is reused. */
    @Test
    void createDecoder_whenSettingsAreUnchanged_returnsTheCachedDecoder() {
        final var client = clientWithJwks(clientKey, SignatureAlgorithm.RS256);

        assertSame(factory.createDecoder(client), factory.createDecoder(client));
    }

    /** A client whose registered keys changed gets a new decoder, which does not accept the old key. */
    @Test
    void createDecoder_whenJwksChange_returnsANewDecoder() throws Exception {
        final var original = clientWithJwks(clientKey, SignatureAlgorithm.RS256);
        final var rotated = RegisteredClient.from(original)
                .clientSettings(settings(otherKey, SignatureAlgorithm.RS256)).build();

        final var oldDecoder = factory.createDecoder(original);
        final var newDecoder = factory.createDecoder(rotated);
        final var assertion = assertion(original, clientKey);

        assertNotSame(oldDecoder, newDecoder);
        assertThrows(JwtException.class, () -> newDecoder.decode(assertion));
    }

    /** A client with keys but no algorithm is refused as invalid_client. */
    @Test
    void createDecoder_whenAlgorithmIsMissing_throwsInvalidClient() {
        final var client = clientBuilder().clientSettings(ClientSettings.builder()
                .setting(RegisteredJwksClientAssertionDecoderFactory.JWKS_SETTING,
                        new JWKSet(clientKey.toPublicJWK()).toString()).build()).build();

        final var error = assertThrows(OAuth2AuthenticationException.class, () -> factory.createDecoder(client));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getError().getErrorCode());
    }

    /** A symmetric algorithm cannot verify registered public keys. */
    @Test
    void createDecoder_whenAlgorithmIsSymmetric_throwsInvalidClient() {
        final var client = clientBuilder().clientSettings(ClientSettings.builder()
                .setting(RegisteredJwksClientAssertionDecoderFactory.JWKS_SETTING,
                        new JWKSet(clientKey.toPublicJWK()).toString())
                .tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256).build()).build();

        final var error = assertThrows(OAuth2AuthenticationException.class, () -> factory.createDecoder(client));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getError().getErrorCode());
    }

    /** Stored keys that are not a JWK set are refused as invalid_client. */
    @Test
    void createDecoder_whenStoredJwksIsNotAJwkSet_throwsInvalidClient() {
        final var client = clientBuilder().clientSettings(ClientSettings.builder()
                .setting(RegisteredJwksClientAssertionDecoderFactory.JWKS_SETTING, "not json")
                .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256).build()).build();

        final var error = assertThrows(OAuth2AuthenticationException.class, () -> factory.createDecoder(client));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getError().getErrorCode());
    }

    /** A client with a jwkSetUrl goes through the framework's factory. */
    @Test
    void createDecoder_whenClientHasJwkSetUrl_usesTheFrameworkFactory() {
        final var client = clientBuilder().clientSettings(ClientSettings.builder()
                .jwkSetUrl("https://client.example.com/jwks.json")
                .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256).build()).build();

        assertNotNull(factory.createDecoder(client));
    }

    /** A client with neither keys nor jwkSetUrl is refused by the framework's factory. */
    @Test
    void createDecoder_whenClientHasNoKeysAtAll_throwsInvalidClient() {
        final var client = clientBuilder().clientSettings(ClientSettings.builder()
                .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256).build()).build();

        final var error = assertThrows(OAuth2AuthenticationException.class, () -> factory.createDecoder(client));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getError().getErrorCode());
    }

    /**
     * Builds a client with registered keys.
     *
     * @param key       the registered public key.
     * @param algorithm the signing algorithm.
     * @return the client.
     */
    private static RegisteredClient clientWithJwks(final RSAKey key, final SignatureAlgorithm algorithm) {
        return clientBuilder().clientSettings(settings(key, algorithm)).build();
    }

    /**
     * Builds the settings of a client with registered keys.
     *
     * @param key       the registered public key.
     * @param algorithm the signing algorithm.
     * @return the settings.
     */
    private static ClientSettings settings(final RSAKey key, final SignatureAlgorithm algorithm) {
        return ClientSettings.builder()
                .setting(RegisteredJwksClientAssertionDecoderFactory.JWKS_SETTING,
                        new JWKSet(key.toPublicJWK()).toString())
                .tokenEndpointAuthenticationSigningAlgorithm(algorithm).build();
    }

    /**
     * Starts a client builder with a fixed identifier.
     *
     * @return the builder.
     */
    private static RegisteredClient.Builder clientBuilder() {
        return RegisteredClient.withId("id-1").clientId("client-1")
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
    }

    /**
     * Signs an assertion for a client.
     *
     * @param client the client the assertion names.
     * @param signer the key that signs.
     * @return the serialized assertion.
     * @throws JOSEException if it cannot be signed.
     */
    private static String assertion(final RegisteredClient client, final RSAKey signer) throws JOSEException {
        final var now = Instant.now();
        final var claims = new JWTClaimsSet.Builder().issuer(client.getClientId()).subject(client.getClientId())
                .audience(ISSUER).jwtID(UUID.randomUUID().toString()).issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(LIFETIME_SECONDS))).build();
        final var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signer.getKeyID()).build(),
                claims);
        jwt.sign(new RSASSASigner(signer));
        return jwt.serialize();
    }
}
