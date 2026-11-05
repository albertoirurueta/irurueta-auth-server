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

package com.irurueta.authserver.authorization.infrastructure.keys;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

// tag::keys-jwk-source[]
/**
 * Maps the domain {@link SigningKey} onto Nimbus JSON Web Keys: the public set lists the public half of every key it
 * is given, whereas the signing set holds the single active key with its private half, decrypted with the
 * {@link AesGcmKeyCipher}.
 */
@Component
@RequiredArgsConstructor
public class SigningKeyJwkMapper {

    /** Decrypts the private half of a key. */
    private final AesGcmKeyCipher cipher;

    /**
     * Builds the set of public keys.
     *
     * @param keys the keys to publish.
     * @return the set, with the public half of each key only.
     * @throws IllegalStateException if a stored key is not a valid JWK.
     */
    public JWKSet toPublicJwkSet(final List<SigningKey> keys) {
        return new JWKSet(keys.stream().map(key -> toJwk(key.publicJwk()).toPublicJWK()).toList());
    }

    /**
     * Builds the set holding the active key, with its private half.
     *
     * @param active the active key, if any.
     * @return the set; empty before the first rotation has created an active key.
     * @throws IllegalStateException if the stored key is not a valid JWK.
     */
    public JWKSet toSigningJwkSet(final Optional<SigningKey> active) {
        return new JWKSet(active.map(key -> toJwk(cipher.decrypt(key.encryptedPrivateJwk()))).stream().toList());
    }

    /**
     * Parses a JSON Web Key.
     *
     * @param json the key as JSON.
     * @return the key.
     * @throws IllegalStateException if the text is not a valid key.
     */
    public JWK toJwk(final String json) {
        try {
            return JWK.parse(json);
        } catch (final ParseException e) {
            throw new IllegalStateException("A stored signing key is not a valid JWK", e);
        }
    }
}
// end::keys-jwk-source[]
