-- version 4
CREATE TABLE IF NOT EXISTS Users ( username string primary, mfa string not null unique, enforcing string, locked BOOLEAN);
INSERT INTO Users SELECT (username, url, enforcing) FROM Devices;

ALTER TABLE Devices RENAME TO Devices_old;
CREATE TABLE Devices(address string primary key, username string not null, publickey string not null unique, endpoint string, attempts integer not null );
INSERT INTO Devices SELECT (address, username, publickey, endpoint, attempts) FROM Devices_old;
DROP TABLE Devices_old;