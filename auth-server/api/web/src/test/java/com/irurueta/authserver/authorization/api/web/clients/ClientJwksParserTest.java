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

package com.irurueta.authserver.authorization.api.web.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientJwksParser}. The keys are generated at run time.
 */
class ClientJwksParserTest {

    /** Size in bits of the generated RSA keys. */
    private static final int KEY_SIZE = 2048;

    /** Parser under test. */
    private final ClientJwksParser parser = new ClientJwksParser();

    /**
     * Verifies that a public key set is accepted and kept.
     *
     * @throws Exception if the key cannot be generated.
     */
    @Test
    void toJson_whenSetHoldsPublicKeys_returnsItsJson() throws Exception {
        final var key = rsaKey();

        final var json = parser.toJson(new JWKSet(key.toPublicJWK()).toJSONObject());

        assertEquals(key.getKeyID(), JWKSet.parse(json).getKeys().getFirst().getKeyID());
        assertFalse(JWKSet.parse(json).getKeys().getFirst().isPrivate());
    }

    /**
     * Verifies that nothing is registered when no set is given.
     */
    @Test
    void toJson_whenSetIsNull_returnsNull() {
        assertNull(parser.toJson(null));
    }

    /**
     * Verifies that a key with private material is refused.
     *
     * @throws Exception if the key cannot be generated.
     */
    @Test
    void toJson_whenSetHoldsPrivateKey_throwsInvalidClientJwksException() throws Exception {
        final var jwks = new JWKSet(rsaKey()).toJSONObject(false);

        final var error = assertThrows(InvalidClientJwksException.class, () -> parser.toJson(jwks));

        assertTrue(error.getMessage().contains("public"));
    }

    /**
     * Verifies that an object that is not a JWK set is refused.
     */
    @Test
    void toJson_whenObjectIsNotAJwkSet_throwsInvalidClientJwksException() {
        assertThrows(InvalidClientJwksException.class, () -> parser.toJson(Map.of("keys", "nope")));
        assertThrows(InvalidClientJwksException.class,
                () -> parser.toJson(Map.of("keys", List.of(Map.of("kty", "unknown")))));
    }

    /**
     * Verifies that a set without keys is refused.
     */
    @Test
    void toJson_whenSetIsEmpty_throwsInvalidClientJwksException() {
        assertThrows(InvalidClientJwksException.class, () -> parser.toJson(Map.of("keys", List.of())));
    }

    /**
     * Verifies that the stored text is converted back to an object and that none stays none.
     *
     * @throws Exception if the key cannot be generated.
     */
    @Test
    void toObject_whenJsonIsGiven_returnsTheSetAsObject() throws Exception {
        final var key = rsaKey().toPublicJWK();

        final var object = parser.toObject(new JWKSet(key).toString());

        assertEquals(new JWKSet(key).toJSONObject(), object);
        assertNull(parser.toObject(null));
    }

    /**
     * Verifies that stored text that is not a JWK set is reported.
     */
    @Test
    void toObject_whenJsonIsNotAJwkSet_throwsInvalidClientJwksException() {
        assertThrows(InvalidClientJwksException.class, () -> parser.toObject(JSONObjectUtils.toJSONString(Map.of())));
    }

    /**
     * Generates an RSA key.
     *
     * @return the key with its private part.
     * @throws Exception if the key cannot be generated.
     */
    private static RSAKey rsaKey() throws Exception {
        return new RSAKeyGenerator(KEY_SIZE).keyID("test-key").generate();
    }
}
