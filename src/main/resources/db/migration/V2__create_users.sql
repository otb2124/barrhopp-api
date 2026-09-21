-- gen_random_uuid() is built into PG13+ core, but explicitly enabling pgcrypto
-- removes any doubt about which PG version/build this runs against.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    display_name    VARCHAR(100) NOT NULL,
    role            VARCHAR(20)  NOT NULL DEFAULT 'USER',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_users_email UNIQUE (email),
    CONSTRAINT chk_users_role CHECK (role IN ('USER', 'ADMIN'))
);

-- Every auth lookup and every login is "find by email" - this is the
-- hot path and needs an index (UNIQUE above already creates one, this
-- is explicit for clarity / in case the constraint implementation changes).
CREATE INDEX idx_users_email ON users (email);