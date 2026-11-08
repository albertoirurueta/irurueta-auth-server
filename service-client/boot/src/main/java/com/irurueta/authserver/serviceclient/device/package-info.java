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
 * Command-line client of the OAuth 2.0 device authorization grant (RFC 8628): requests a device code, shows the user
 * code and verification URI, and polls the token endpoint until the user approves the request.
 * <p>
 * Everything here is active only under the {@code device-flow} Spring profile, so the regular service-client
 * application is not affected.
 */
package com.irurueta.authserver.serviceclient.device;
