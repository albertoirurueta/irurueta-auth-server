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

package com.irurueta.authserver.authorization.keys;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

class TemporaryJwkConfigurationTest {

    @Test
    void jwkSource_generatesDistinctRsaKeysOfExpectedSize() throws Exception {
        final var configuration = new TemporaryJwkConfiguration();
        final var selector = new JWKSelector(new JWKMatcher.Builder().build());

        final var first = (RSAKey) configuration.jwkSource().get(selector, null).get(0);
        final var second = (RSAKey) configuration.jwkSource().get(selector, null).get(0);

        assertThat(first.isPrivate()).isTrue();
        assertThat(first.toRSAPublicKey().getModulus().bitLength()).isEqualTo(TemporaryJwkConfiguration.KEY_SIZE);
        assertThat(first.getKeyID()).isNotEqualTo(second.getKeyID());
        assertThat(first.toRSAPublicKey()).isNotEqualTo(second.toRSAPublicKey());
    }
}
