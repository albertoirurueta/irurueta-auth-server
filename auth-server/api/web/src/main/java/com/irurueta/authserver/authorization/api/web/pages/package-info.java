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
 * Rendering of the server-rendered HTML pages. Each page is an operation of the contract
 * {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml}: its controller implements the interface generated from
 * it, whose method answers the page as a {@code text/html} string, and renders the page with
 * {@link com.irurueta.authserver.authorization.api.web.pages.PageRenderer}.
 */
package com.irurueta.authserver.authorization.api.web.pages;
