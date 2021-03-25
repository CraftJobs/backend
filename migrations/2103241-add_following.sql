CREATE TABLE following (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    follower_user_id UUID NOT NULL,
    following_user_id UUID NOT NULL,
    UNIQUE(follower_user_id, following_user_id)
);
