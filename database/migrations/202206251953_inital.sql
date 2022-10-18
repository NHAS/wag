-- version 1
CREATE TABLE IF NOT EXISTS RegistrationTokens ( token string primary key, username string not null unique );
CREATE TABLE IF NOT EXISTS Totp ( address string primary key, publickey string not null unique, username string not null unique, url string not null unique, enforcing string, attempts integer not null );

