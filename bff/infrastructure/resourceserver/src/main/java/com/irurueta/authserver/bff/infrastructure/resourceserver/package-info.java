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
 * Resource-server adapter of the BFF: implements the
 * {@link com.irurueta.authserver.bff.domain.documents.DocumentGateway} port with the REST client generated from the
 * resource server's contract ({@code apis/resource-server/rest-server/resource-server-api-v1.yaml}). Every call carries
 * the access token of the signed-in user, which never reaches the browser, and every failure is translated into a
 * domain exception, so no HTTP or OAuth2 type crosses the port.
 */
package com.irurueta.authserver.bff.infrastructure.resourceserver;
