# Wag

Wag adds 2fa and device enrolment to wireguard.    

It allows you to restrict routes based on 2fa, while allowing other routes to remain public as long as a client has a valid public key.  

# Sponsorship 

This work was very kindly supported by <a href='https://www.aurainfosec.com/'>Aura Information Security</a>. 

![image](https://user-images.githubusercontent.com/6820641/181147262-c7baa5a5-36b2-4153-b01f-5064226ec56e.png)


# Requirements

glibc 2.34 or higher  
go1.16+

The wireguard device must be running before wag is started.  
  
`iptables` and `wg-quick` must be installed. 
Wag must be run as root, to manage `iptables` and the `wireguard` device itself.  
   
Forwarding must be enabled in `sysctl`.

```
sysctl -w net.ipv4.ip_forward=1
```

It is a good idea to have `SaveConfig` set to `true` in the server configuration file, so that changes to the peers list made by wag will be saved.  

```
[Interface]
Address = 192.168.1.1/24
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

Supported commands: `start`, `cleanup`, `registration`, `devices`, `firewall`, `version`, `upgrade`
  
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
``` 

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
  -address string
        Device address
  -del
        Completely remove device blocks wireguard access
  -list
        List devices with 2fa entries
  -lock
        Locked account/device access to mfa routes
  -mfa_sessions
        Get list of deivces with active authorised sessions
  -reset
        Reset locked account/device
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
  
To authenticate the user should browse to the servers vpn address, in this case `192.168.1.1:8080`, where they will be prompted for their 2fa code.  
The configuration file specifies how long a session can live for, before expiring.  


# Configuration file reference
  
`Proxied`: Respect the `X-Forward-For` directive, must ensure that you are securing the X-Forward-For directive in your reverse proxy  
`HelpMail`: The email address that is shown on the prompt page  
`Lockout`: Number of times a person can attempt mfa authentication before their account locks  
  
`ExternalAddress`: The public address of the server, the place where wireguard is listening to the internet, and where clients can reach the `/register_device` endpoint    

`MaxSessionLifetimeMinutes`: After authenticating, a device will be allowed to talk to privileged routes for this many minutes, if -1, timeout is disabled  
`SessionInactivityTimeoutMinutes`: If a device has not sent data in `n` minutes, it will be required to reauthenticate, if -1 timeout is disabled  
  
`DatabaseLocation`: Where to load the sqlite3 database from, it will be created if it does not exist  
`Issuer`: TOTP issuer, the name that will get added to the TOTP app  
`DNS`: An array of DNS servers that will be automatically used, and set as "Allowed" (no MFA)  
`Acls`: Defines the `Groups` and `Policies` that restrict routes  
  
`Webserver`: Object that contains the public and tunnel listening addresses of the webserver  
`WebServer.<endpoint>.ListenAddress`: Listen address for endpoint  
`WebServer.<endpoint>.CertPath`: TLS Certificate path for endpoint  
`WebServer.<endpoint>.KeyPath`: TLS key for endpoint  
  
`WgDevName`: The wireguard tunnel device name that wag will manage  

`Wireguard`: Object that contains the wireguard device configuration
          "DevName": "wg0",
        "ListenPort": 53230,
        "PrivateKey": "AN EXAMPLE KEY",
        "Address": "192.168.1.1/24",
        "MTU": 1420,
        "PersistentKeepAlive": 25
Full config example
```json
{
    "Lockout": 5,
    "HelpMail": "help@example.com",
    "MaxSessionLifetimeMinutes": 2,
    "SessionInactivityTimeoutMinutes": 1,
    "ExternalAddress": "192.168.121.61",
    "DatabaseLocation": "devices.db",
    "Issuer": "192.168.121.61",
    "DNS": ["1.1.1.1"],
    "Webserver": {
        "Public": {
            "ListenAddress": "192.168.121.61:8080"
        },
        "Tunnel": {
            "ListenAddress": "192.168.1.1:8080"
        }
    },
    "Wireguard": {
        "DevName": "wg0",
        "ListenPort": 53230,
        "PrivateKey": "AN EXAMPLE KEY",
        "Address": "192.168.1.1/24",
        "MTU": 1420,
        "PersistentKeepAlive": 25
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


# Testing
```sh
cd router
sudo go test -v .
```

Sudo is required to load the eBPF program into the kernel.