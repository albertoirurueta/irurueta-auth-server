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
 * Use cases of the BFF: Spring services over the domain ports. Like the resource server's, they demarcate no
 * transaction: they touch no transactional store (the documents live on the resource server, behind
 * {@link com.irurueta.authserver.bff.domain.documents.DocumentGateway}), and holding a database connection open
 * across a remote call would only waste it.
 */
package com.irurueta.authserver.bff.application;
