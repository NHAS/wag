-- version 4
CREATE TABLE IF NOT EXISTS Users ( username string primary key, mfa string not null unique, enforcing string, locked BOOLEAN DEFAULT FALSE not null);
INSERT INTO Users (username, mfa, enforcing) SELECT username, url, enforcing FROM Devices;

ALTER TABLE Devices RENAME TO Devices_old;
CREATE TABLE Devices(address string primary key, username string not null, publickey string not null unique, endpoint string, attempts integer DEFAULT 0 not null);
INSERT INTO Devices (address,username, publickey, endpoint, attempts) SELECT address, username, publickey, endpoint, attempts FROM Devices_old;
DROP TABLE Devices_old;