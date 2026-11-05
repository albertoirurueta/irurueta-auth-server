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

-- tag::users-schema[]
CREATE TABLE users
(
    id         uuid                     NOT NULL,
    username   varchar(100)             NOT NULL,
    enabled    boolean                  NOT NULL DEFAULT TRUE,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uq_users_username UNIQUE (username)
);

CREATE TABLE user_authorities
(
    user_id   uuid         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    authority varchar(100) NOT NULL,
    PRIMARY KEY (user_id, authority)
);

CREATE TABLE user_passwords
(
    user_id          uuid                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    encoded_password varchar(255)             NOT NULL,
    updated_at       timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id)
);
-- end::users-schema[]
