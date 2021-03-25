CREATE TABLE users (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    username TEXT NOT NULL,
    username_lower TEXT NOT NULL,
    password_hashed TEXT NOT NULL,
    email TEXT NOT NULL,
    full_name TEXT NOT NULL,
    rate_lower SMALLINT NOT NULL DEFAULT -1,
    rate_higher SMALLINT NOT NULL DEFAULT -1,
    avatar_url TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'DEVELOPER',
    rate_range_type TEXT NOT NULL DEFAULT 'FLAT',
    admin BOOL DEFAULT FALSE,
    alpha BOOL DEFAULT FALSE,
    description TEXT DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()::timestamp
);

CREATE TABLE looking_for (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    user_id UUID NOT NULL,
    looking_for_type TEXT NOT NULL,
    UNIQUE(user_id, looking_for_type)
);

CREATE TABLE reputation_log (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    from_user_id UUID NOT NULL,
    to_user_id UUID NOT NULL,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    amount INT NOT NULL,
    message TEXT NOT NULL
);

CREATE TABLE connections (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    user_id UUID NOT NULL,
    connection_type TEXT NOT NULL,
    link TEXT NOT NULL,
    UNIQUE(user_id, connection_type)
);
