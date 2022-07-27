# Wag

Wag adds 2fa and device enrolment to wireguard.    

It allows you to restrict routes based on 2fa, while allowing other routes to remain public as long as a client has a valid public key.  

# Sponsorship 

This work was very kindly supported by <a href='https://www.aurainfosec.com/'>Aura Information Security</a>. 

# Requirements

The wireguard device must be running before wag is started.  
Wag must not be run behind a reverse proxy just yet. It doesnt support `X-Forward-For` and reads the clients real IP address.  
  
Iptables must be installed. 
Wag must be run as root, to manage `iptables` and the `wireguard` device itself.  
   

Forwarding must be enabled in `sysctl`.

```
sysctl -w net.ipv4.ip_forward=1
```

It is a good idea to have `SaveConfig` set to `true` in the server configuration file, so that changes to the peers list made by wag will be saved.  

```
[Interface]
Address = 10.27.0.2/24
SaveConfig = true
ListenPort = 51820
PrivateKey = <omitted>
```
Example `/etc/wireguard/wg0.conf`   

```
systemctl start wg-quick@wg0
```

# Setup instructions

```
git clone git@github.com:NHAS/wag.git
cd wag
go build

cp example_config config.json

sudo ./wag
```

# Management

The root user is able to manage the wag server with the following command:
  
```
wag subcommand [-options]
```
  
All commands need to be able to load the config file. And thus support `-config`  
  
`start`: starts the wag server  
  
`registration`:  Deals with creating, deleting and listing the registration tokens
```
Usage of registration:
  -add
        Create a new enrolment token
  -del
        Delete existing enrolment token
  -list
        List tokens
  -token string
        Manually set registration token (Optional)
  -username string
        Username of device
```  

`devices`: Manages MFA and device access  
```
Usage of devices:
  -del
        Completely remove device blocks wireguard access
  -device string
        Device address
  -list
        List devices with 2fa entries
  -lock
        Locked account/device access to mfa routes
  -reset
        Reset locked account/device
  -sessions
        Get list of currently active authorised sessions
```

# User guide

## Starting wag

1. Create your `wg0.conf` and start the service `wg-quick@wg0`
2. Edit the configuration file `WgDevName` to `WgDevName`:`wg0`
3. `sudo ./wag start`

## Creating new registration tokens

First generate a token.  
```
# ./wag registration -add -username tester
token,username
e83253fd9962c68f73aa5088604f3f425d58a963bfb5c0889cca54d63a34b2e3,tester
```

Then curl said token.  
```
curl http://public.server.address:8082/register_device?key=e83253fd9962c68f73aa5088604f3f425d58a963bfb5c0889cca54d63a34b2e3
```

The service will return a fully templated response:
```
[Interface]
PrivateKey = <omitted>
Address = 10.27.0.7

[Peer]
Endpoint =  public.server.address:51820
PublicKey = pnvl40WiRt++0NucEGexlpfwWA8QzBYg2+8ZWZJvejA=
AllowedIPs = 10.0.1.1/32, 10.27.0.1/32, 10.234.0.1/32, 10.14.0.2/24
PersistentKeepAlive = 10
```

Which can then be written to a config file. 

## Entering MFA  
  
To authenticate the user should browse to the servers vpn address, in this case `10.27.0.1:8082`, where they will be prompted for their 2fa code.  
The configuration file specifies how long a session can live for, before expiring.  


# Configuration file reference
  
`WgDevName`: The wireguard tunnel device name that wag will manage  
`Lockout`: Number of times a person can attempt mfa authentication before their account locks  
`ExternalAddress`: The public address of the server, the place where wireguard is listening to the internet, and where clients can reach the `/register_device` endpoint  
`SessionTimeoutMinutes`: After authenticating, a device will be allowed to talk to privileged routes for this many minutes  
`Listen`: Object that contains the public and tunnel listening addresses of the webserver  
`DatabaseLocation`: Where to load the sqlite3 database from, it will be created if it does not exist  
`Issuer`: TOTP issuer, the name that will get added to the TOTP app  
`Routes`: Object that contains the `AuthRequired` and `Public` routes list.    
  
Full config example
```
{
    "WgDevName": "wg0",
    "Lockout": 5,
    "Listen: {
        "Public": ":8080",
        "Tunnel": "10.0.0.1:80"
    },
    "SessionTimeoutMinutes": 10,
    "ExternalAddress": "192.168.56.3",
    "DatabaseLocation": "devices.db",
    "Issuer": "192.168.56.3",
    "Routes": {
        "AuthRequired": [
            "10.234.0.1/32",
            "10.14.0.2/24"
        ],
        "Public": [
            "10.0.1.1/32"
        ]
    }
}

```
# Limitations
- Only supports clients with one `AllowedIP`, which is perfect for site to site, or client -> server based architecture.  
- IPv4 only.
- Linux only
- Doesnt support X-Forward-For, or X-Real-IP
- No TLS (yet)
