-- version 2
ALTER TABLE Totp RENAME TO Devices;
ALTER TABLE Devices ADD endpoint string;