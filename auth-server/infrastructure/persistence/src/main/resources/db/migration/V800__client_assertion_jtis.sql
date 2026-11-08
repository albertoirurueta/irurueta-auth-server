-- Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--         http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- tag::client-assertion-schema[]
-- One row per client assertion (private_key_jwt) already accepted, so the same assertion cannot be presented twice
-- (RFC 7523 section 3 allows an authorization server to refuse a replayed jti). A row is useful only until the
-- assertion expires and is purged afterwards.
CREATE TABLE client_assertion_jtis
(
    client_id  varchar(100)             NOT NULL,
    jti        varchar(255)             NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    PRIMARY KEY (client_id, jti)
);

CREATE INDEX ix_client_assertion_jtis_expires_at ON client_assertion_jtis (expires_at);
-- end::client-assertion-schema[]
