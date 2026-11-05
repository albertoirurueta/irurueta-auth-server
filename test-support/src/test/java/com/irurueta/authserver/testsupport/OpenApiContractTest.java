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

package com.irurueta.authserver.testsupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests of {@link OpenApiContract}.
 */
class OpenApiContractTest {

    /** A contract in YAML that shares a parameter and a response through references. */
    private static final String CONTRACT = """
            openapi: 3.1.0
            info: {title: Test API, version: 1.0.0}
            security:
              - bearer: [ ]
            paths:
              /api/items/{id}:
                parameters:
                  - $ref: '#/components/parameters/Id'
                get:
                  operationId: getItem
                  tags: [ Items ]
                  responses:
                    '200':
                      description: The item
                      content:
                        application/json:
                          schema: {$ref: '#/components/schemas/Item'}
                    '401':
                      $ref: '#/components/responses/Unauthorized'
                put:
                  operationId: putItem
                  tags: [ Items ]
                  security:
                    - bearer: [ admin ]
                  requestBody:
                    required: true
                    content:
                      application/json:
                        schema: {$ref: '#/components/schemas/Item'}
                  responses:
                    '204': {description: Stored}
              /api/items:
                get:
                  operationId: listItems
                  security: [ ]
                  parameters:
                    - {name: q, in: query, schema: {type: string}}
                  responses:
                    '200':
                      description: The items
                      content:
                        application/json:
                          schema: {type: array, items: {$ref: '#/components/schemas/Item'}}
                        text/plain:
                          schema: {type: string}
              /other:
                get:
                  operationId: other
                  responses:
                    '200': {description: Not part of the API}
            components:
              securitySchemes:
                bearer: {type: http, scheme: bearer, bearerFormat: JWT, description: Ignored}
              parameters:
                Id: {name: id, in: path, required: true, schema: {type: string}}
              responses:
                Unauthorized: {description: Missing token}
              schemas:
                Item:
                  type: object
                  required: [ id ]
                  properties:
                    name: {type: string}
                    id: {type: string}
            """;

    /** The same API as served at runtime: JSON, everything inline, other descriptions and an extra schema. */
    private static final String SERVED = """
            {"openapi":"3.1.0","info":{"title":"Test API","version":"1.0.0","description":"Other text"},
             "paths":{
              "/api/items":{"get":{"operationId":"listItems","parameters":[{"name":"q","in":"query"}],
               "responses":{"200":{"description":"x","content":{
                "text/plain":{"schema":{"type":"string"}},
                "application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/Item"}}}}}}}},
              "/api/items/{id}":{
               "get":{"operationId":"getItem","tags":["Items"],"security":[{"bearer":[]}],
                "parameters":[{"name":"id","in":"path","required":true}],
                "responses":{"200":{"description":"y","content":{"application/json":{"schema":
                 {"$ref":"#/components/schemas/Item"}},"application/problem+json":{"schema":
                 {"$ref":"#/components/schemas/Item"}}}},"401":{"description":"z","content":{"application/json":
                 {"schema":{"$ref":"#/components/schemas/Item"}}}}}},
               "put":{"operationId":"putItem","tags":["Items"],"security":[{"bearer":["admin"]}],
                "parameters":[{"name":"id","in":"path","required":true}],
                "requestBody":{"required":true,"content":{"application/json":{"schema":
                 {"$ref":"#/components/schemas/Item"}}}},
                "responses":{"204":{"description":"w"}}}}},
             "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer","bearerFormat":"JWT"}},
              "schemas":{"Item":{"type":"object","required":["id"],"properties":{"id":{},"name":{}}},
               "Extra":{"type":"object"}}}}
            """;

    /** Prefix of the API paths. */
    private static final String PREFIX = "/api/";

    /**
     * Verifies that a contract and the equivalent served document have the same summary once what the server
     * documents by itself (an extra schema, its return type under a media type or an answer the contract declares
     * without a body) is left out.
     */
    @Test
    void restrictTo_whenServedDocumentMatchesContract_summariesAreEqual() {
        final var contract = OpenApiContract.summarize(OpenApiContract.parse(CONTRACT), PREFIX);
        final var served = OpenApiContract.summarize(OpenApiContract.parse(SERVED), PREFIX);

        assertNotEquals(contract, served);
        assertEquals(contract, OpenApiContract.restrictTo(served, contract));
    }

    /**
     * Verifies that a media type the contract declares and the server does not serve is still reported.
     */
    @Test
    void restrictTo_whenDeclaredMediaTypeIsMissing_summariesDiffer() {
        final var contract = OpenApiContract.summarize(OpenApiContract.parse(CONTRACT), PREFIX);
        final var served = OpenApiContract.summarize(
                OpenApiContract.parse(SERVED.replace("\"text/plain\"", "\"text/csv\"")), PREFIX);

        assertNotEquals(contract, OpenApiContract.restrictTo(served, contract));
    }

    /**
     * Verifies what the summary of an operation, a response and a schema says, and that paths outside the prefix are
     * left out.
     */
    @Test
    void summarize_whenContractIsGiven_describesOperationsResponsesAndSchemas() {
        final var summary = OpenApiContract.summarize(OpenApiContract.parse(CONTRACT), PREFIX);

        assertEquals("Test API 1.0.0", summary.get("info"));
        assertEquals("type=http, scheme=bearer, bearerFormat=JWT", summary.get("securityScheme bearer"));
        assertEquals("operationId=putItem; tags=[Items]; security=[bearer[admin]]; parameters=[path:id:true]; "
                + "requestBody=required=true [application/json:Item]", summary.get("PUT /api/items/{id}"));
        assertEquals("operationId=listItems; tags=[]; security=[]; parameters=[query:q:false]; requestBody=none",
                summary.get("GET /api/items"));
        assertEquals("declared", summary.get("GET /api/items 200"));
        assertEquals("array<Item>", summary.get("GET /api/items 200 content application/json"));
        assertEquals("string", summary.get("GET /api/items 200 content text/plain"));
        assertEquals("declared", summary.get("GET /api/items/{id} 401"));
        assertFalse(summary.keySet().stream().anyMatch(key -> key.startsWith("GET /api/items/{id} 401 content")));
        assertEquals("properties=[id, name]; required=[id]", summary.get("schema Item"));
        assertFalse(summary.keySet().stream().anyMatch(key -> key.contains("/other")));
    }

    /**
     * Verifies that an operation the served document lacks shows up as a difference.
     */
    @Test
    void summarize_whenOperationIsMissing_summariesDiffer() {
        final var contract = OpenApiContract.summarize(OpenApiContract.parse(CONTRACT), PREFIX);
        final var served = OpenApiContract.summarize(OpenApiContract.parse(SERVED.replace("\"put\"", "\"post\"")),
                PREFIX);

        assertNotEquals(contract, OpenApiContract.restrictTo(served, contract));
        assertTrue(served.containsKey("POST /api/items/{id}"));
    }

    /**
     * Verifies that a contract file is read from disk.
     *
     * @param directory temporary directory of the test.
     * @throws Exception if the file cannot be written or read.
     */
    @Test
    void read_whenFileExists_parsesIt(@TempDir final Path directory) throws Exception {
        final var file = directory.resolve("contract.yaml");
        Files.writeString(file, CONTRACT, StandardCharsets.UTF_8);

        assertEquals(OpenApiContract.parse(CONTRACT), OpenApiContract.read(file));
    }

    /**
     * Verifies that a reference to another document is rejected rather than silently ignored.
     */
    @Test
    void summarize_whenReferenceIsNotLocal_throwsIllegalArgumentException() {
        final var document = OpenApiContract.parse(
                CONTRACT.replace("'#/components/responses/Unauthorized'", "'common.yaml#/Unauthorized'"));

        assertThrows(IllegalArgumentException.class, () -> OpenApiContract.summarize(document, PREFIX));
    }

    /**
     * Verifies that a reference to a missing component is rejected.
     */
    @Test
    void summarize_whenReferenceIsUnresolved_throwsNullPointerException() {
        final var document = OpenApiContract.parse(
                CONTRACT.replace("'#/components/responses/Unauthorized'", "'#/components/responses/Missing'"));

        assertThrows(NullPointerException.class, () -> OpenApiContract.summarize(document, PREFIX));
    }
}
