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

/**
 * What a binding keeps of a certificate sent to the account API: its fingerprint, which identifies it, and its subject,
 * which only tells the bindings apart.
 *
 * @param fingerprintSha256 SHA-256 fingerprint of the DER form, as 64 lower case hexadecimal digits.
 * @param subjectDn         subject distinguished name, in the RFC 2253 form.
 */
public record PresentedCertificate(String fingerprintSha256, String subjectDn) {
}
