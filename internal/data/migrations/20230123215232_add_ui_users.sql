-- version 7
CREATE TABLE IF NOT EXISTS AdminUsers ( username primary key, passwd_hash text not null unique, locked string, last_login string, ip string, date_added string not null );
CREATE TABLE IF NOT EXISTS Configurations ( date primary key, configuration text not null unique);