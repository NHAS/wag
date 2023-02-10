-- version 8
ALTER TABLE Devices ADD preshared_key TEXT DEFAULT "unset" NOT NULL;

-- Fix an old bug of having mfa be unique, which really aint very helpful
ALTER TABLE Users RENAME TO Users_old;
CREATE TABLE Users ( username string primary key, mfa string not null, enforcing string, locked BOOLEAN DEFAULT FALSE not null, mfa_type string DEFAULT "unset" NOT NULL);
INSERT INTO Users (username, mfa, enforcing, locked, mfa_type) SELECT username, mfa, enforcing, locked, mfa_type FROM Users_old;
DROP TABLE Users_old;


