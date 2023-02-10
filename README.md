# Wag

Wag adds 2fa and device enrolment to wireguard.    

It allows you to restrict routes based on 2fa, while allowing other routes to remain public as long as a client has a valid public key.  

# Sponsorship 

This work was very kindly supported by <a href='https://www.aurainfosec.com/'>Aura Information Security</a>. 

![image](https://user-images.githubusercontent.com/6820641/181147262-c7baa5a5-36b2-4153-b01f-5064226ec56e.png)


# Requirements


`iptables` must be installed.  
Wag must be run as root, to manage `iptables` and the `wireguard` device.  
   
Forwarding must be enabled in `sysctl`.  
  
```
sysctl -w net.ipv4.ip_forward=1
```

Wag does not need `wg-quick` or other equalivent as long as the kernel supports wireguard.  

# Setup instructions

Both options require a kernel newer than 4.15+;
  
Binary release (requires glibc 2.31+):  
```
curl -L $(curl -s https://api.github.com/repos/NHAS/wag/releases/latest | jq -M -r '.assets[0].browser_download_url') -o wag
sudo ./wag gen-config

sudo ./wag start -config <generated_config_name>
```
  
From source (will require go1.19, npm, clang, llvm-strip):  
```
git clone git@github.com:NHAS/wag.git
cd wag
make

cp example_config.json config.json

sudo ./wag start
```

If running behind a reverse proxy, `X-Forwarded-For` must be set.

# Management

The root user is able to manage the wag server with the following command:
  
```
wag subcommand [-options]
```

Supported commands: `start`, `cleanup`, `reload`, `version`, `firewall`, `registration`, `devices`, `users`, `webadmin`, `upgrade`, `gen-config`
  
`start`: starts the wag server  
```
Usage of start:
  Start wag server (does not daemonise)
  -config string
        Configuration file location (default "./config.json")
```

`cleanup`: Will remove all firewall forwards, and shutdown the wireguard device  

`reload`: Reloads ACLs from configuration

`version`: Display the version of wag

`firewall`: Get firewall rules
```  
Usage of firewall:
  -list
        List firewall rules
  -socket string
        Wag socket to act on (default "/tmp/wag.sock")

``` 

`registration`:  Deals with creating, deleting and listing the registration tokens
```
Usage of registration:
  -add
        Create a new enrolment token
  -del
        Delete existing enrolment token
  -group value
        Manually set user group (can supply multiple -group, or use -groups for , delimited group list, useful for OIDC)
  -groups string
        Set user groups manually, ',' delimited list of groups, useful for OIDC
  -list
        List tokens
  -overwrite string
        Add registration token for an existing user device, will overwrite wireguard public key (but not 2FA)
  -socket string
        Wag socket to act on (default "/tmp/wag.sock")
  -token string
        Manually set registration token (Optional)
  -username string
        User to add device to
```  

`devices`: Manages devices  
```
Usage of devices:
  -address string
        Address of device
  -del
        Remove device and block wireguard access
  -list
        List wireguard devices
  -lock
        Lock device access to mfa routes
  -mfa_sessions
        Get list of devices with active authorised sessions
  -socket string
        Wag control socket to act on (default "/tmp/wag.sock")
  -unlock
        Unlock device
  -username string
        Owner of device (indicates that command acts on all devices owned by user)
```
  
`users`: Manages users MFA and can delete all users devices
```
Usage of users:
  -del
        Delete user and all associated devices
  -list
        List users, if '-username' supply will filter by user
  -lockaccount
        Lock account disable authention from any device, deauthenticates user active sessions
  -reset-mfa
        Reset MFA details, invalids all session and set MFA to be shown
  -socket string
        Wag socket location, (default "/tmp/wag.sock")
  -unlockaccount
        Unlock a locked account, does not unlock specific device locks (use device -unlock -username <> for that)
  -username string
        Username to act upon
```

`webadmin`: Manages the administrative users for the web UI
```
Usage of webadmin:
  -add
        Add web administrator user (requires -password)
  -del
        Delete admin user
  -list
        List web administration users, if '-username' supply will filter by user
  -lockaccount
        Lock admin account disable login for this web administrator user
  -password string
        Username to act upon
  -socket string
        Wag instance control socket (default "/tmp/wag.sock")
  -unlockaccount
        Unlock a web administrator account
  -username string
        Admin Username to act upon
```

`upgrade`: Pin all ebpf programs, shutdown wag server and optionally copy in the new binary all while leaving the XDP firewall online  
Note, this will not restart the server after shutdown, you will manually need to start the server after with your preferred service manager (`systemctl start wag`)
```
Usage of upgrade:
  -force
        Disable compatiablity checks
  -hash string
        Version hash from new wag version (find this by doing ./wag version -local)
  -manual
        Shutdown the server in upgrade mode but will not copy or automatically check the new wag binary
  -path string
        File path to new wag executable
  -socket string
        Wag socket location, (default "/tmp/wag.sock")
```

# User guide

## Installing wag

1. Copy `wag`, `config.json` to `/opt/wag`
2. Generate a wireguard private key with `wg genkey` set `PrivateKey` in the example config to it
3. Copy (or link) `wag.service` to `/etc/systemd/system/` and start/enable the service

## Creating new registration tokens

First generate a token.  
```
# ./wag registration -add -username tester
token,username
e83253fd9962c68f73aa5088604f3f425d58a963bfb5c0889cca54d63a34b2e3,tester
```

Then curl said token.  
```
curl http://public.server.address:8080/register_device?key=e83253fd9962c68f73aa5088604f3f425d58a963bfb5c0889cca54d63a34b2e3
```

The service will return a fully templated response:
```
[Interface]
PrivateKey = <omitted>
Address = 192.168.1.1

[Peer]
Endpoint =  public.server.address:51820
PublicKey = pnvl40WiRt++0NucEGexlpfwWA8QzBYg2+8ZWZJvejA=
AllowedIPs = 10.7.7.7/32, 192.168.1.1/32, 192.168.3.4/32, 192.168.3.5/32
PersistentKeepAlive = 10
```

Which can then be written to a config file. 

## Entering MFA  
  
To authenticate the user should browse to the servers vpn address, in the example, case `192.168.1.1:8080`, where they will be prompted for their 2fa code.  
The configuration file specifies how long a session can live for, before expiring.  


# Configuration file reference
  
`Proxied`: Respect the `X-Forward-For` directive, must ensure that you are securing the X-Forward-For directive in your reverse proxy  
`HelpMail`: The email address that is shown on the prompt page  
`Lockout`: Number of times a person can attempt mfa authentication before their account locks  
  
`ExternalAddress`: The public address of the server, the place where wireguard is listening to the internet, and where clients can reach the `/register_device` endpoint    
  
`MaxSessionLifetimeMinutes`: After authenticating, a device will be allowed to talk to privileged routes for this many minutes, if -1, timeout is disabled  
`SessionInactivityTimeoutMinutes`: If a device has not sent data in `n` minutes, it will be required to reauthenticate, if -1 timeout is disabled  
  
`DatabaseLocation`: Where to load the sqlite3 database from, it will be created if it does not exist  
`Socket`: Wag control socket, changing this will allow multiple wag instances to run on the same machine  
`Acls`: Defines the `Groups` and `Policies` that restrict routes  
  
`Webserver`: Object that contains the public and tunnel listening addresses of the webserver  

`WebServer.Public.ListenAddress`: Listen address for endpoint  
`WebServer.Tunnel.Port`: Port for in-vpn-tunnel webserver, this does not take a full IP address, as the tunnel listener should *never* be outside the wireguard device

`WebServer.<endpoint>.CertPath`: TLS Certificate path for endpoint  
`WebServer.<endpoint>.KeyPath`: TLS key for endpoint  
  
`Authenticators`: Object that contains configurations for the authentication methods wag provides  
`Authenticators.Issuer`: TOTP issuer, the name that will get added to the TOTP app  
`Authenticators.DomainURL`: Full url of the vpn authentication endpoint, required for `webauthn` and `oidc`
`Authenticators.DefaultMethod`: String, default method the user will be presented, if not specified a list of methods is displayed to the user (possible values: `webauth`, `totp`, `oidc`)    
`Authenticators.Methods`: String array, enabled authentication methods, e.g ["totp","webauthn","oidc"]

`Authenticators.OIDC`: Object that contains `OIDC` specific configuration options
`Authenticators.OIDC.IssuerURL`: Identity provider endpoint, e.g `http://localhost:8080/realms/account`
`Authenticators.OIDC.ClientID`:  OIDC identifier for application
`Authenticators.OIDC.ClientSecret`: OIDC secret
`Authenticators.OIDC.GroupsClaimName`: Not yet used. 
  
`Wireguard`: Object that contains the wireguard device configuration  
`Wireguard.DevName`: The wireguard device to attach or to create if it does not exist, will automatically add peers (no need to configure peers with `wg-quick`)  
`Wireguard.ListenPort`: Port that wireguard will listen on  
`Wireguard.PrivateKey`: The wireguard private key, can be generated with `wg genkey`  
`Wireguard.Address`: Subnet the VPN is responsible for  
`Wireguard.MTU`: Maximum transmissible unit defaults to 1420 if not set for IPv4 over Ethernet  
`Wireguard.PersistentKeepAlive`: Time between wireguard keepalive heartbeats to keep NAT entries alive, defaults to 25 seconds
`Wireguard.DNS`: An array of DNS servers that will be automatically used, and set as "Allowed" (no MFA)  
   
`ManagementUI`: Object that contains configurations for the webadministration portal. It is not recommend to expose this portal, I recommend setting `ListenAddress` to `127.0.0.1`/`localhost` and then use ssh forwarding to expose it  
`ManagementUI.Enabled`: Enable the web UI  
`ManagementUI.ListenAddress`: Listen address to expose the management UI on  
`ManagementUI.CertPath`: TLS Certificate path for management endpoint  
`ManagementUI.KeyPath`: TLS key for the management endpoint  
  
Full config example
```json
{
    "Lockout": 5,
    "HelpMail": "help@example.com",
    "MaxSessionLifetimeMinutes": 2,
    "SessionInactivityTimeoutMinutes": 1,
    "ExternalAddress": "192.168.121.61",
    "DatabaseLocation": "devices.db",
    "Socket":"/tmp/wag.sock",
    "Webserver": {
        "Public": {
            "ListenAddress": "192.168.121.61:8080"
        },
        "Tunnel": {
            "Port": "8080"
        }
    },
    "ManagementUI": {
        "ListenAddress": "127.0.0.1:4433",
        "Enabled": true
    },
    "Authenticators": {
        "Issuer": "vpn.test",
        "DomainURL": "https://vpn.test:8080",
        "DefaultMethod":"webauthn",
        "Methods":["totp","webauthn", "oidc"],
        "OIDC": {
            "IssuerURL": "http://localhost:8080/",
            "ClientSecret": "<OMITTED>",
            "ClientID": "account",
            "GroupsClaimName": "groups"
        }
    },
    "Wireguard": {
        "DevName": "wg0",
        "ListenPort": 53230,
        "PrivateKey": "AN EXAMPLE KEY",
        "Address": "192.168.1.1/24",
        "MTU": 1420,
        "PersistentKeepAlive": 25,
        "DNS": ["1.1.1.1"]
    },
    "Acls": {
        "Groups": {
            "group:nerds": [
                "toaster",
                "tester",
                "abc"
            ],
        },
        "Policies": {
            "*": {
                "Allow": [
                    "10.7.7.7",
                    "google.com"
                ]
            },
            "username": {
                  "Allow":[ "10.0.0.1/32"]
            },
            "group:nerds": {
                "Mfa": [
                    "192.168.3.4/32"
                ],
                "Allow": [
                    "192.168.3.5/32"
                ]
            }
        }
    }
}

```
# Limitations
- Only supports clients with one `AllowedIP`, which is perfect for site to site, or client -> server based architecture.  
- IPv4 only.
- Linux only
- Modern kernel 4.15+ at least (needs ebpf and xdp)


# Development 

## Testing
```sh
cd internal/router
sudo go test -v .
```

Sudo is required to load the eBPF program into the kernel.

## Building a release


If you havent built the release docker image (used because it has a stable version of glibc)
```
cd builder
sudo docker build -t wag_builder .
cd ..

make docker
```


# Unoffical Docker

https://github.com/lachlan2k/wag-docker/