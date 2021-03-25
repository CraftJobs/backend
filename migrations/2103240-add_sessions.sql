CREATE TABLE sessions (
    id UUID NOT NULL PRIMARY KEY UNIQUE,
    token TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()::timestamp,
    expires_at TIMESTAMP NOT NULL
);
