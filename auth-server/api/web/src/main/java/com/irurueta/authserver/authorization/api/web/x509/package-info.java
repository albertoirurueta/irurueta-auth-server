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

/**
 * X.509 client certificate authentication: a certificate presented on a dedicated TLS port, or forwarded by a trusted
 * reverse proxy in a header, signs in the user it is bound to (by the SHA-256 fingerprint of the certificate) at
 * {@code POST /login/x509}, the form of the login page, with the CSRF token. Everything is off unless
 * {@code authserver.x509.enabled} is {@code true}.
 */
package com.irurueta.authserver.authorization.api.web.x509;
