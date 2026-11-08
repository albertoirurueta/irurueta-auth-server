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
package com.irurueta.authserver.authorization.api.web.x509;

import java.nio.file.Path;

/**
 * The key store that holds the server certificate of the dedicated TLS port.
 *
 * @param location where the key store is.
 * @param password password of the key store and of its key.
 * @param type     type of the key store, such as {@code PKCS12}.
 */
public record X509TlsKeyStore(Path location, String password, String type) {

    /**
     * Describes the key store without its password.
     *
     * @return the description.
     */
    @Override
    public String toString() {
        return "X509TlsKeyStore[location=" + location + ", type=" + type + "]";
    }
}
