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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Unit tests of {@link PrivateKeyJwkResolver}.
 */
class PrivateKeyJwkResolverTest {

    /** Registration the assertion is for. */
    private static final ClientRegistration REGISTRATION = ClientRegistration.withRegistrationId("service-client")
            .clientId("client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .tokenUri("https://auth.example.com/oauth2/token")
            .build();

    /**
     * Verifies that an inline PEM gives the key pair, the algorithm and the key id.
     *
     * @throws Exception if the public key cannot be read.
     */
    @Test
    void apply_whenKeyIsInline_buildsTheSigningJwk() throws Exception {
        final var pair = TestKeys.rsaKeyPair();
        final var resolver = new PrivateKeyJwkResolver(
                new ServiceClientKeyProperties(TestKeys.pkcs8Pem(pair), null, "kid-1"));

        final var jwk = (RSAKey) resolver.apply(REGISTRATION);

        assertEquals(((RSAPublicKey) pair.getPublic()).getModulus(), jwk.toRSAPublicKey().getModulus());
        assertTrue(jwk.isPrivate());
        assertEquals(JWSAlgorithm.RS256, jwk.getAlgorithm());
        assertEquals("kid-1", jwk.getKeyID());
    }

    /**
     * Verifies that an environment variable that carries the PEM with literal {@code \n} sequences still works.
     */
    @Test
    void apply_whenInlineKeyHasEscapedNewlines_buildsTheSigningJwk() {
        final var pem = TestKeys.pkcs8Pem(TestKeys.rsaKeyPair()).replace("\n", "\\n");
        final var resolver = new PrivateKeyJwkResolver(new ServiceClientKeyProperties(pem, null, null));

        assertTrue(resolver.apply(REGISTRATION).isPrivate());
    }

    /**
     * Verifies that a PEM file is read when there is no inline key.
     *
     * @param directory temporary directory.
     * @throws IOException if the file cannot be written.
     */
    @Test
    void apply_whenKeyIsAFile_buildsTheSigningJwk(@TempDir final Path directory) throws IOException {
        final var file = directory.resolve("key.pem");
        Files.writeString(file, TestKeys.pkcs8Pem(TestKeys.rsaKeyPair()), StandardCharsets.UTF_8);
        final var resolver = new PrivateKeyJwkResolver(new ServiceClientKeyProperties(null, file, null));

        assertTrue(resolver.apply(REGISTRATION).isPrivate());
    }

    /**
     * Verifies that the assertion Spring Security builds from the key verifies with the public half.
     *
     * @throws Exception if the assertion cannot be parsed or verified.
     */
    @Test
    void apply_whenUsedBySpringConverter_assertionIsSignedWithTheConfiguredKey() throws Exception {
        final var pair = TestKeys.rsaKeyPair();
        final var resolver = new PrivateKeyJwkResolver(
                new ServiceClientKeyProperties(TestKeys.pkcs8Pem(pair), null, "kid-1"));
        final var converter = new NimbusJwtClientAuthenticationParametersConverter<OAuth2ClientCredentialsGrantRequest>(
                resolver);

        final var parameters = converter.convert(new OAuth2ClientCredentialsGrantRequest(REGISTRATION));

        final var assertion = SignedJWT.parse(parameters.getFirst("client_assertion"));
        assertTrue(assertion.verify(new RSASSAVerifier((RSAPublicKey) pair.getPublic())));
        assertEquals("client", assertion.getJWTClaimsSet().getSubject());
        assertEquals("kid-1", assertion.getHeader().getKeyID());
        assertFalse(parameters.containsKey("client_secret"));
    }

    /**
     * Verifies that no key at all is refused with a message that names the settings.
     */
    @Test
    void apply_whenNoKeyIsConfigured_throwsIllegalStateException() {
        final var resolver = new PrivateKeyJwkResolver(new ServiceClientKeyProperties(" ", null, null));

        final var error = assertThrows(IllegalStateException.class, () -> resolver.apply(REGISTRATION));

        assertTrue(error.getMessage().contains("private-key"));
    }

    /**
     * Verifies that a file that does not exist is refused.
     *
     * @param directory temporary directory.
     */
    @Test
    void apply_whenFileIsMissing_throwsIllegalStateException(@TempDir final Path directory) {
        final var resolver = new PrivateKeyJwkResolver(
                new ServiceClientKeyProperties(null, directory.resolve("missing.pem"), null));

        assertThrows(IllegalStateException.class, () -> resolver.apply(REGISTRATION));
    }

    /**
     * Verifies that a PKCS#1 key is refused with an explanation.
     */
    @Test
    void apply_whenKeyIsPkcs1_throwsIllegalStateException() {
        final var pem = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        final var resolver = new PrivateKeyJwkResolver(new ServiceClientKeyProperties(pem, null, null));

        final var error = assertThrows(IllegalStateException.class, () -> resolver.apply(REGISTRATION));

        assertTrue(error.getMessage().contains("PKCS#8"));
    }

    /**
     * Verifies that garbage is refused without echoing it.
     */
    @Test
    void apply_whenKeyIsNotAKey_throwsIllegalStateExceptionWithoutTheText() {
        final var pem = "-----BEGIN PRIVATE KEY-----\nnot-a-valid-key!!\n-----END PRIVATE KEY-----\n";
        final var resolver = new PrivateKeyJwkResolver(new ServiceClientKeyProperties(pem, null, null));

        final var error = assertThrows(IllegalStateException.class, () -> resolver.apply(REGISTRATION));

        assertFalse(error.getMessage().contains("not-a-valid-key"));
    }
}
