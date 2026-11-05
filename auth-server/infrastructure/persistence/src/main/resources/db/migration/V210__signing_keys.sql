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

-- tag::keys-schema[]
CREATE TABLE signing_keys
(
    kid                   varchar(64)              NOT NULL,
    alg                   varchar(20)              NOT NULL,
    public_jwk            text                     NOT NULL,
    private_jwk_encrypted text                     NOT NULL,
    status                varchar(20)              NOT NULL,
    created_at            timestamp with time zone NOT NULL,
    activated_at          timestamp with time zone,
    retired_at            timestamp with time zone,
    PRIMARY KEY (kid),
    CONSTRAINT ck_signing_keys_status CHECK (status IN ('NEXT', 'ACTIVE', 'RETIRED'))
);

-- At most one key can sign at any time.
CREATE UNIQUE INDEX uq_signing_keys_single_active ON signing_keys (status) WHERE status = 'ACTIVE';
-- end::keys-schema[]
