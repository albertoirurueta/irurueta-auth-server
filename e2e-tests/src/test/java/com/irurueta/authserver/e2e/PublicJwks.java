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
package com.irurueta.authserver.e2e;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Builds the public JWK sets a client registers with the admin API ({@code jwks}) from the public keys the tests
 * generate at run time. Only public parameters are ever written.
 */
final class PublicJwks {

    /** Length in bytes of a coordinate of a P-256 point. */
    private static final int P256_COORDINATE_BYTES = 32;

    /** Mapper that builds the JSON. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** Line length of a PEM body. */
    private static final int PEM_LINE_LENGTH = 64;

    /**
     * Not instantiable.
     */
    private PublicJwks() {
    }

    /**
     * Builds a JWK set with one RSA signature key.
     *
     * @param key the public key.
     * @return the JWK set.
     */
    static ObjectNode rsa(final RSAPublicKey key) {
        final var jwk = JSON.createObjectNode();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("n", base64Url(unsigned(key.getModulus(), 0)));
        jwk.put("e", base64Url(unsigned(key.getPublicExponent(), 0)));
        return set(jwk);
    }

    /**
     * Builds a JWK set with one P-256 key, the key of a certificate for example.
     *
     * @param key the public key; it must be on the P-256 curve.
     * @return the JWK set.
     */
    static ObjectNode p256(final ECPublicKey key) {
        final var jwk = JSON.createObjectNode();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", base64Url(unsigned(key.getW().getAffineX(), P256_COORDINATE_BYTES)));
        jwk.put("y", base64Url(unsigned(key.getW().getAffineY(), P256_COORDINATE_BYTES)));
        return set(jwk);
    }

    /**
     * Encodes an RSA private key (PKCS#8 encoding) as an unencrypted PEM text.
     *
     * @param pkcs8 the PKCS#8 encoding of the key.
     * @return the PEM text, with {@code \n} line ends.
     */
    static String privateKeyPem(final byte[] pkcs8) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + new String(Base64.getMimeEncoder(PEM_LINE_LENGTH, "\n".getBytes(StandardCharsets.US_ASCII))
                .encode(pkcs8), StandardCharsets.US_ASCII)
                + "\n-----END PRIVATE KEY-----\n";
    }

    /**
     * Wraps a key in a set.
     *
     * @param jwk the key.
     * @return the set.
     */
    private static ObjectNode set(final ObjectNode jwk) {
        final var set = JSON.createObjectNode();
        set.putArray("keys").add(jwk);
        return set;
    }

    /**
     * Returns the big-endian unsigned bytes of a number.
     *
     * @param value  the number.
     * @param length the length to pad to, or zero for the minimal length.
     * @return the bytes.
     */
    private static byte[] unsigned(final BigInteger value, final int length) {
        final var bytes = value.toByteArray();
        final var start = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
        final var stripped = Arrays.copyOfRange(bytes, start, bytes.length);
        if (length == 0 || stripped.length == length) {
            return stripped;
        }
        final var padded = new byte[length];
        System.arraycopy(stripped, 0, padded, length - stripped.length, stripped.length);
        return padded;
    }

    /**
     * Encodes bytes as unpadded base64url.
     *
     * @param bytes the bytes.
     * @return the text.
     */
    private static String base64Url(final byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
