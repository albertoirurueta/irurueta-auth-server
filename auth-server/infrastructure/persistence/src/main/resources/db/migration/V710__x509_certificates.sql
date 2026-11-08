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

-- tag::x509-schema[]
-- One row per client certificate bound to a user. The certificate is recognised by the SHA-256 fingerprint of its DER
-- encoding (lower case hexadecimal), which is unique: one certificate belongs to one account. The subject DN is kept
-- only to tell the bindings apart.
CREATE TABLE x509_certificates
(
    id                 uuid                     NOT NULL,
    user_id            uuid                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    fingerprint_sha256 char(64)                 NOT NULL,
    subject_dn         varchar(1000)            NOT NULL,
    created_at         timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uq_x509_certificates_fingerprint UNIQUE (fingerprint_sha256),
    CONSTRAINT ck_x509_certificates_fingerprint_shape CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX ix_x509_certificates_user_id ON x509_certificates (user_id);
-- end::x509-schema[]
