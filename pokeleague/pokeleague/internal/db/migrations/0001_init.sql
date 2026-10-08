-- Pokémon League schema.
--
-- Invariants live in the database as well as in Go: application validation
-- gives friendly errors, constraints guarantee correctness even if a bug,
-- a script or a future service bypasses the application.

CREATE TABLE trainers (
    id            uuid        PRIMARY KEY,
    username      text        NOT NULL CHECK (username ~ '^[A-Za-z0-9_]{3,32}$'),
    email         text        NOT NULL CHECK (char_length(email) BETWEEN 3 AND 254),
    password_hash text        NOT NULL,
    role          text        NOT NULL DEFAULT 'trainer'
                              CHECK (role IN ('trainer', 'gym_leader', 'admin')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Case-insensitive uniqueness ("Ash" and "ash" are the same trainer).
CREATE UNIQUE INDEX trainers_username_lower_key ON trainers (lower(username));
CREATE UNIQUE INDEX trainers_email_lower_key    ON trainers (lower(email));

CREATE TABLE tournaments (
    id               uuid        PRIMARY KEY,
    host_id          uuid        NOT NULL REFERENCES trainers (id) ON DELETE RESTRICT,
    name             text        NOT NULL CHECK (char_length(name) BETWEEN 3 AND 100),
    description      text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    region           text        NOT NULL CHECK (region IN
                        ('kanto','johto','hoenn','sinnoh','unova','kalos','alola','galar','paldea')),
    pokemon_type     text        NOT NULL CHECK (pokemon_type IN
                        ('normal','fire','water','grass','electric','ice','fighting','poison','ground',
                         'flying','psychic','bug','rock','ghost','dragon','dark','steel','fairy')),
    capacity         integer     NOT NULL CHECK (capacity BETWEEN 2 AND 1024),
    -- Denormalised count of rows in registrations, maintained in the same
    -- transaction as every insert/delete there. Gives O(1) "spots left".
    registered_count integer     NOT NULL DEFAULT 0,
    status           text        NOT NULL DEFAULT 'open'
                                 CHECK (status IN ('open', 'closed', 'cancelled')),
    starts_at        timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    -- Last line of defence for the capacity invariant: even if every lock in
    -- the application were removed, the database would refuse to overbook.
    CONSTRAINT tournaments_registered_count_within_capacity
        CHECK (registered_count >= 0 AND registered_count <= capacity)
);

-- Keyset pagination indexes: (sort column, id) matches ORDER BY col, id and
-- the row-value predicate (col, id) > ($1, $2), so each page is an index
-- range scan regardless of how deep the client has paged.
CREATE INDEX tournaments_starts_at_id_idx  ON tournaments (starts_at, id);
CREATE INDEX tournaments_created_at_id_idx ON tournaments (created_at, id);
CREATE INDEX tournaments_name_id_idx       ON tournaments (name, id);
CREATE INDEX tournaments_region_starts_idx ON tournaments (region, starts_at, id);
-- Postgres does not index foreign keys automatically.
CREATE INDEX tournaments_host_id_idx       ON tournaments (host_id);

-- The many-to-many relationship: trainers <-> tournaments.
CREATE TABLE registrations (
    id            uuid        PRIMARY KEY,
    tournament_id uuid        NOT NULL REFERENCES tournaments (id) ON DELETE CASCADE,
    -- RESTRICT, not CASCADE: silently deleting registrations would leave
    -- tournaments.registered_count out of sync with reality.
    trainer_id    uuid        NOT NULL REFERENCES trainers (id) ON DELETE RESTRICT,
    lead_pokemon  text        NOT NULL CHECK (char_length(lead_pokemon) BETWEEN 1 AND 40),
    created_at    timestamptz NOT NULL DEFAULT now(),

    -- One registration per trainer per tournament. This also serves as the
    -- index for "who is registered for tournament X".
    CONSTRAINT registrations_tournament_trainer_key UNIQUE (tournament_id, trainer_id)
);

CREATE INDEX registrations_trainer_id_idx ON registrations (trainer_id, created_at DESC);

-- Server-side state for refresh tokens (rotation + reuse detection).
CREATE TABLE refresh_tokens (
    id                 uuid        PRIMARY KEY,
    trainer_id         uuid        NOT NULL REFERENCES trainers (id) ON DELETE CASCADE,
    family_id          uuid        NOT NULL,
    token_hash         bytea       NOT NULL,
    expires_at         timestamptz NOT NULL,
    session_expires_at timestamptz NOT NULL,
    revoked_at         timestamptz,
    replaced_by        uuid        REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    user_agent         text        NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT refresh_tokens_expiry_within_session CHECK (expires_at <= session_expires_at)
);

CREATE INDEX refresh_tokens_family_id_idx  ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_trainer_id_idx ON refresh_tokens (trainer_id);
CREATE INDEX refresh_tokens_session_exp_idx ON refresh_tokens (session_expires_at);
