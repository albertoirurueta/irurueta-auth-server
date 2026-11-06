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

package com.irurueta.authserver.bff.domain.documents;

import java.util.List;

/**
 * Port to the documents the signed-in user keeps on the resource server. An implementation acts on behalf of the user
 * of the current request, never returns {@code null} and reports every failure with one of the exceptions below, so no
 * transport or framework type reaches its callers.
 */
public interface DocumentGateway {

    /**
     * Lists the documents the signed-in user may see.
     *
     * @return the documents, empty when there are none.
     * @throws DocumentsUnauthorizedException if the session holds no valid token for the user.
     * @throws DocumentsForbiddenException    if the user may not list documents.
     * @throws DocumentsUnavailableException  if the resource server cannot be reached or fails.
     */
    List<Document> list();

    /**
     * Deletes one document of the signed-in user.
     *
     * @param id identifier of the document.
     * @throws DocumentsUnauthorizedException if the session holds no valid token for the user.
     * @throws DocumentsForbiddenException    if the user may not delete documents.
     * @throws DocumentNotFoundException      if the document does not exist or belongs to someone else.
     * @throws DocumentsUnavailableException  if the resource server cannot be reached or fails.
     */
    void deleteById(String id);
}
