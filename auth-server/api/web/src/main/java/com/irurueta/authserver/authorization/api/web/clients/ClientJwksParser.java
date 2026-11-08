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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.text.ParseException;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Parses and validates the public JWK set a client registers for {@code private_key_jwt} and self-signed mutual TLS
 * authentication, and converts it between the JSON object of the contract and the JSON text the domain keeps.
 */
@Component
public class ClientJwksParser {

    // tag::clients-auth-settings[]
    /**
     * Validates a JWK set sent by an administrator and returns its JSON text. Only public keys are accepted: a key
     * with private material (including a symmetric key) is refused.
     *
     * @param jwks the JWK set as a JSON object, or {@code null}.
     * @return the JWK set as JSON text, or {@code null} when none was given.
     * @throws InvalidClientJwksException if the object is not a JWK set, has no keys or has a private key.
     */
    public String toJson(final Map<String, Object> jwks) {
        if (jwks == null) {
            return null;
        }
        final JWKSet parsed;
        try {
            parsed = JWKSet.parse(JSONObjectUtils.toJSONString(jwks));
        } catch (ParseException | IllegalArgumentException e) {
            throw new InvalidClientJwksException("jwks is not a valid JWK set", e);
        }
        if (parsed.getKeys().isEmpty()) {
            throw new InvalidClientJwksException("jwks must contain at least one key");
        }
        if (parsed.getKeys().stream().anyMatch(JWK::isPrivate)) {
            throw new InvalidClientJwksException("jwks must contain public keys only");
        }
        return parsed.toString();
    }
    // end::clients-auth-settings[]

    /**
     * Converts the JSON text of a registered JWK set to the JSON object of the contract.
     *
     * @param json the JWK set as JSON text, or {@code null}.
     * @return the JWK set as an object, or {@code null} when there is none.
     * @throws InvalidClientJwksException if the stored text is not a JWK set.
     */
    public Map<String, Object> toObject(final String json) {
        if (json == null) {
            return null;
        }
        try {
            return JWKSet.parse(json).toJSONObject(true);
        } catch (ParseException e) {
            throw new InvalidClientJwksException("the registered jwks is not a valid JWK set", e);
        }
    }
}
