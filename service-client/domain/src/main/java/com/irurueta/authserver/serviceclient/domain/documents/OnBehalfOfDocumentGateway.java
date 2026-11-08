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

package com.irurueta.authserver.serviceclient.domain.documents;

import java.util.List;

/**
 * Port to the documents on the resource server, read on behalf of a user: the subject token of the user is exchanged
 * for a token for the resource server (RFC 8693). An implementation never returns {@code null} and reports every
 * failure as a {@link DocumentAccessException}, so no transport or framework type reaches its callers.
 */
public interface OnBehalfOfDocumentGateway {

    /**
     * Lists the documents the user may see.
     *
     * @param subjectToken access token of the user, which is exchanged and never logged.
     * @return the documents, empty when there are none.
     * @throws DocumentAccessException if the exchange is refused, the resource server refuses the exchanged token or
     *                                 cannot be reached.
     */
    List<Document> listDocumentsAs(String subjectToken);
}
