# Wag [![Go](https://github.com/NHAS/wag/actions/workflows/test_and_deploy.yml/badge.svg)](https://github.com/NHAS/wag/actions/workflows/test_and_deploy.yml)

Wag adds MFA, route restriction and device enrolment to wireguard.    

Key Features:
- Define routes which require MFA authorisation, or public always accessible routes
- Easy API for registering new clients
- High Availability
- Real time user updates and notifications
- Multiple MFA integrations
  - Security Key
  - SSO
  - PAM
  - TOTP
  
## Administration

![image](https://github.com/user-attachments/assets/9b639991-b795-438d-bd45-8b4e106ef802)

![image](https://github.com/user-attachments/assets/d629030b-e845-4461-b609-561a7cf944d4)

![image](https://github.com/user-attachments/assets/c12efdd3-c731-4d21-9a30-c207b0997e23)

![image](https://github.com/user-attachments/assets/a3d684e8-9879-4f27-89fb-312f1dceb280)

## User UI

![image](https://github.com/user-attachments/assets/7be16906-8afa-44cd-9d31-2f53a98a4d3b)

![image](https://github.com/user-attachments/assets/e0fd2995-223d-4e12-b7b4-27ef7b01b5e7)

![image](https://github.com/user-attachments/assets/ae8380a5-d749-44ef-b445-c41d24e126f0)




# Sponsorship 

This work was very kindly supported by <a href='https://www.aurainfosec.com/'>Aura Information Security</a>. 

![image](https://user-images.githubusercontent.com/6820641/181147262-c7baa5a5-36b2-4153-b01f-5064226ec56e.png)


# Requirements

Forwarding must be enabled in `sysctl`.  
  
```sh
sysctl -w net.ipv4.ip_forward=1
#Or for ipv6

sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.accept_ra=2
sysctl -w net.ipv6.conf.all.accept_redirects=1
sysctl -w net.ipv6.conf.all.accept_source_route=1
```

# Setup instructions

## Docker Compose

Please find the docker compose here, you will need to define a configuration file in `/cfg`:

```yaml
---
services:
  wag:
    image: wagvpn/wag:latest # ghcr.io/nhas/wag:unstable # Unstable branch
    container_name: wag
    restart: always
    ports:
      - 11371:11371/udp
    cap_add:
      - NET_ADMIN
     ports:
      - '4433:4433/tcp' # Admin page
      - '8081:8081/tcp' # Public registration page
      - '53230:53230/udp' # Wireguard port
    volumes:
      - ./wag/config/:/cfg/:z
      - ./wag/data/:/data:z
    devices:
      - /dev/net/tun:/dev/net/tun
```


## Manual

`iptables` and `libpam` must be installed.  
Wag must be run as root, to manage `iptables` and the `wireguard` device.  

Binary release (requires glibc 2.31+):  
```sh
curl -L $(curl -s https://api.github.com/repos/NHAS/wag/releases/latest | jq -M -r '.assets[0].browser_download_url') -o wag

sudo ./wag start -config <generated_config_name>
```
  
From source (will require `go1.23.1`, `npm`):  
```sh
git clone git@github.com:NHAS/wag.git
cd wag
make

cp example_config.json config.json

sudo ./wag start
```

# Management

## UI

After you have set up wag and enabled the administrative user interface, it will create the first admin for you, the password will be output to STDOUT. Then you can log in and manage users there.  

![image](https://github.com/user-attachments/assets/e18bf61e-d809-44c3-80e2-0fe4f5269029)


## CLI

The root user is able to manage the wag server with the following command:
  
```sh
wag subcommand [-options]
```

Supported commands: `start`, `cleanup`, `version`, `firewall`, `registration`, `devices`, `users`, `webadmin`
  
`start`: starts the wag server  
```sh
Usage of start:
  Start wag server (does not daemonise)
  -join string
        Cluster join token
  -config string
        Configuration file location (default "./config.json")
```

`cleanup`: Will remove all firewall forwards, and shutdown the wireguard device  

`version`: Display the version of wag

`firewall`: Get firewall rules
```sh
Usage of firewall:
  -list
        List firewall rules
  -socket string
        Wag socket to act on (default "/tmp/wag.sock")

``` 

`registration`:  Deals with creating, deleting and listing the registration tokens
```sh
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
```sh
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
```sh
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
```sh
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

# Administration guide

## Manual installation of Wag

1. Copy `wag`, `config.json` to `/opt/wag`
2. Generate a wireguard private key with `wg genkey` set `PrivateKey` in the example config to it
3. Copy (or link) `wag.service` to `/etc/systemd/system/` and start/enable the service

## Creating new registration tokens

First generate a token.  
```sh
# ./wag registration -add -username tester
token,username
e83253fd9962c68f73aa5088604f3f425d58a963bfb5c0889cca54d63a34b2e3,tester
```

Then curl said token.  
```sh
curl http://public.server.address:8080/register_device?key=e83253fd9962c68f73aa5088604f3f425d58a963bfb5c0889cca54d63a34b2e3
```

The service will return a fully templated response:
```ini
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

## Signing in to the Management console

Make sure that you have `Webserver.Management.Enabled` set as `true`, then do the following from the console:

```sh
sudo ./wag webadmin -add -username <your_username> -password <your-password-here>
```
Then browse to your management listening address and enter your credentials.

The web interface itself cannot add administrative users.


# Configuration file reference
  
`NumberProxies`: The number of trusted reverse proxies before the client, makes wag respect the `X-Forward-For` directive and parses the client IP from it correctly  

`Socket`: Wag control socket, changing this will allow multiple wag instances to run on the same machine  
`GID`: The group ID that the wag control socket (`/tmp/wag*`) should be set to  

`NAT`: Turn on or off masquerading  
`ExposePorts`: Expose ports on the VPN server to the client (adds rules to IPtables) example: [ "443/tcp", "100-200/udp" ]  
`CheckUpdates`: If enabled (off by default) the management UI will show an alert if a new version of wag is available. This talks to `api.github.com`   

`Acls`: Defines the `Groups` and `Policies` that restrict routes, this is **only respected on first run**, use the web UI to edit them during runtime.  
`Policies`: A map of group or user names to policy objects which contain the wag firewall & route capture rules. The most specific match governs the type of access a user has to a route, e.g if you have a `/16` defined as MFA, but one ip address in that range as allow that is `/32` then the `/32` will take precedence over the `/16`   
`Policies.<policy name>.Mfa`: The routes and services that require Mfa to access  
`Policies.<policy name>.Public`: Routes and services that do not require authorisation
`Policies.<policy name>.Deny`: Deny access to this route  
  
`Webserver`: Object that contains the public and tunnel listening addresses of the webserver  

`WebServer.Acme`: Object to contain the ACME details, such as email and CA provider
`WebServer.Acme.CAProvider`: The provider for your ACME certs, defaults to `https://acme-staging-v02.api.letsencrypt.org/directory`  
`WebServer.Acme.CloudflareDNSToken`: The cloudflare DNS token to do DNS-01 ACME, optional, if not defined then HTTP-01 will be used. You'll have to define your DNS A/AAAA records to point to the public web address.
  
`Webserver.Lockout`: Number of times a person can attempt mfa authentication before their account locks  
  
`WebServer.Public.ListenAddress`: Listen address for the public registration endpoint
`WebServer.Public.Domain`: Domain for the registration API  
`WebServer.Public.TLS`: Boolean, enable TLS on this endpoint (will automatically use ACME if configured with preference to static certificates)   
`WebServer.Public.CertificatePath`: Path to certificate to load in on first run  
`WebServer.Public.PrivateKeyPath`: Path to private key to load into wag on first run
`WebServer.Public.ExternalAddress`: External address to be baked in to generated wireguard configs, i.e where your wireguard connections connect to.  
`WebServer.Public.DownloadConfigFileName`: The config name to serve toe clients, defaults to `wg0.conf`

`WebServer.Tunnel`: Object that contains configurations for the MFA portal and the MFA methods wag provides  
`WebServer.Tunnel.Domain`: Domain for the MFA portal tunnel   
`WebServer.Tunnel.TLS`: Boolean, enable TLS on this endpoint (will automatically use ACME if configured with preference to static certificates)   
`WebServer.Tunnel.CertificatePath`: Path to certificate to load in on first run  
`WebServer.Tunnel.PrivateKeyPath`: Path to private key to load into wag on first run
`WebServer.Tunnel.Port`: Port for in-vpn-tunnel webserver, this does not take a full IP address, as the tunnel listener should *never* be outside the wireguard device
`WebServer.Tunnel.Domain`: The domain of your MFA portal  
`WebServer.Tunnel.MaxSessionLifetimeMinutes`: How long a session can last, if -1, timeout is disabled   
`WebServer.Tunnel.SessionInactivityTimeoutMinutes`: How long a device can be idle before it has to reauthenticate, if -1 timeout is disabled  
`WebServer.Tunnel.HelpMail`: Help mail to display on the UI  
`WebServer.Tunnel.DefaultMethod`: String, default method the user will be presented, if not specified a list of methods is displayed to the user (possible values: `webauth`, `totp`, `oidc`, `pam`)    
`WebServer.Tunnel.Issuer`: OTP issuer, the name that will get added to the TOTP app or Webauthn device
`WebServer.Tunnel.Methods`: String array, enabled authentication methods, e.g `["totp","webauthn","oidc", "pam"]`. 

`WebServer.Tunnel.OIDC`: Object that stores the OIDC settings  
`WebServer.Tunnel.OIDC.IssuerURL`: The URL of your identity provider , e.g `http://localhost:8080/realms/account`  
`WebServer.Tunnel.OIDC.ClientID`: OIDC identifier for application  
`WebServer.Tunnel.OIDC.ClientSecret`: OIDC client secret  
`WebServer.Tunnel.OIDC.DeviceUsernameClaim`: The claim within the oidc token that contains the users device name  
`WebServer.Tunnel.OIDC.Scopes`: Array of scopes to request from your identity provider, defaults to `openid`  
`WebServer.Tunnel.OIDC.GroupsClaimName`: Claim that contains user groups to map into wag groups  

`WebServer.Tunnel.PAM`:  Object that stores the PAM settings
`WebServer.Tunnel.PAM.ServiceName`: Name of PAM-Auth file in `/etc/pam.d/`  will default to `/etc/pam.d/login` if unset or empty  
  
`WebServer.Management`: Object that contains configurations for the webadministration portal. It is not recommend to expose this portal, I recommend setting `ListenAddress` to `127.0.0.1`/`localhost` and then use ssh forwarding to expose it  
`WebServer.Management.Enabled`: Enable the web UI  
`WebServer.Management.Domain`: Domain for the management interface  
`WebServer.Management.TLS`: Boolean, enable TLS on this endpoint (will automatically use ACME if configured with preference to static certificates)   
`WebServer.Management.ListenAddress`: Listen address to expose the management UI on  
`WebServer.Management.CertificatePath`: Path to certificate to load in on first run  
`WebServer.Management.PrivateKeyPath`: Path to private key to load into wag on first run
`WebServer.Management.Password`: Object that contains password authentication configuration options for the admin login.  
`WebServer.Management.Password.Enabled`: Boolean, enable password login (defaults to true).  
`WebServer.Management.OIDC`: Object that contains `OIDC` specific configuration options for the admin login.
`WebServer.Management.OIDC.Enabled`: Boolean to enable OIDC login on the admin page.  
`WebServer.Management.OIDC.IssuerURL`: Identity provider endpoint, e.g `http://localhost:8080/realms/account`  
`WebServer.Management.OIDC.ClientID`:  OIDC identifier for application  
`WebServer.Management.OIDC.ClientSecret`: OIDC secret  
`WebServer.Management.OIDC.IssuerURL`: The administrative page domain  
  
`Clustering`: Object containing the clustering details  
`Clustering.Name`: Name of this cluster (defaults to `wag`)  
`Clustering.ClusterState`: Same as the etcd cluster state setting, can be either `new`, create a new cluster, or `existing`. If you are joining an existing cluster, use `start -join` rather than this  
`Clustering.ETCDLogLevel`: Level of logging for the embedded etcd server to emit, options `info`, `error`  
`Clustering.Witness`: Is the node a witness node, i.e one that does not start a wireguard device, or management UI, but replicates events for the RAFT concensus  
`Clustering.DatabaseLocation`: Path to write the etcd database  
`Clustering.TLSManagerListenURL`: URL for generating certificates for the wag cluster, must be reachable by all nodes, typically automatically set by `start -join`  
`Clustering.TLSManagerStorage`: Path to store certificates for the cluster  

`Wireguard`: Object that contains the wireguard device configuration  
`Wireguard.DevName`: The wireguard device to attach or to create if it does not exist, will automatically add peers (no need to configure peers with `wg-quick`)  
`Wireguard.ListenPort`: Port that wireguard will listen on  
`Wireguard.PrivateKey`: The wireguard private key, can be generated with `wg genkey`  
`Wireguard.Address`: Subnet the VPN is responsible for  
`Wireguard.MTU`: Maximum transmissible unit defaults to 1420 if not set for IPv4 over Ethernet  
`Wireguard.DNS`: An array of DNS servers that will be automatically used, and set as "Allowed" (no MFA)  
   
  
Full config example
```json
{
    "Socket": "/tmp/wag.sock",
    "NumberProxies": 0,
    "ExposePorts": [
        "443/tcp",
        "100-200/udp"
     ],
    "NAT": true,
    "Webserver": {
        "Lockout": 5,

        "Tunnel": {
            "Domain": "vpn.test",
            "Port": "8080",

            "MaxSessionLifetimeMinutes": 2,
            "SessionInactivityTimeoutMinutes": 1,

            "HelpMail": "help@example.com",

            "DefaultMethod": "totp",
            "Issuer": "vpn.test",
            "Methods": [
                "totp"
            ],
            "OIDC": {
                "IssuerURL": "",
                "ClientSecret": "",
                "ClientID": "",
                "GroupsClaimName": "",
                "DeviceUsernameClaim": "",
                "Scopes": []
            },
            "PAM": {
                "ServiceName": ""
            }
        },

        "Public": {
            "ListenAddress": ":8081",
         

            "ExternalAddress": "192.168.121.61",
            "DownloadConfigFileName": "wg0.conf"

        },
        "Management": {
            "Enabled": true,
            "ListenAddress": "127.0.0.1:4433",
            "Password": {
                "Enabled": true
            },
            "OIDC": {
                "IssuerURL": "",
                "ClientSecret": "",
                "ClientID": "",
                "Enabled": false
            }
        }
    },

    "Wireguard": {
        "DevName": "wg1",
        "ListenPort": 53230,
        "PrivateKey": "uP2iyvfBFkz7Ks6yZmXbTN2PDSOaLb0zKTziMhBYs0E=",
        "Address": "192.168.122.1/24",
        "ServerPersistentKeepAlive": 0
    },
    "Clustering": {
        "ClusterState": "new",
        "ETCDLogLevel": "error",
        "ListenAddresses": [
            "https://127.0.0.1:2380"
        ],
        "TLSManagerListenURL": "https://127.0.0.1:3434",
        "DatabaseLocation": "/your/data/path"
    },
    "Acls": {
        "Groups": {
            "group:administrators": [
                "toaster",
                "tester"
            ],
            "group:nerds": [
                "toaster",
                "tester",
                "abc"
            ]
        },
        "Policies": {
            "*": {
                "Mfa": [
                    "1.1.1.1",
                    "12.2.3.2",
                    "22.22.22.2",
                    "33.33.33.33",
                    "4.4.5.5",
                    "5.5.5.5"
                ],
                "Allow": [
                    "7.7.7.7",
                    "google.com"
                ]
            },
            "group:administrators": {
                "Mfa": [
                    "8.8.8.8"
                ]
            },
            "group:nerds": {
                "Mfa": [
                    "192.168.3.4/32"
                ],
                "Allow": [
                    "192.168.3.5/32"
                ]
            },
            "tester": {
                "Mfa": [
                    "192.168.3.0/24",
                    "192.168.5.0/24"
                ],
                "Allow": [
                    "4.3.3.3/32"
                ]
            },
            "toaster": {
                "Allow": [
                    "1.1.1.1/32"
                ]
            }
        }
    }
}

```

   
## Defining ACL rules
  
The `Policies` section allows you to define what routes should be both captured by the VPN and what ports and protocols are allowed through Wag.  
  
Rules use the subnet prefix length to determine which rule applies. The most *specific* match is use to determine the level of user access to a route.   
For example:  
```json
 "*": {
                "Mfa": [
                     "10.0.0.0/16"
                ],
                "Allow": [
                    "10.0.1.1/32",
                ]
            },
```
Users will be able to access `10.0.1.1` **without** MFA as the match is more specific. This change occured in v6.0.0, previously MFA routes would always take precedence.   
  
  
Additionally if multiple policies are defined for a single route they are composed with MFA rules taking preference.  
For example:  
```json
 "*": {
            "Mfa": [
                  "10.0.0.0/16",
                  "10.0.1.1/32 22/tcp",
            ]
  },
 "group:users": {
            "Allow": [
                  "10.0.1.1/32 443/tcp",
            ]
 }
```
All users will be able to access `22/tcp` on the `10.0.1.1/32` host, but users in the `group:users` will be able to access `443/tcp` on that host as well, along with `22/tcp` when authorized.  

As of **[version number, yet to be released]** you can now define deny rules which will block access to a route.

Example: 

```json
 "*": {
            "Allow": [
                  "10.0.0.0/16",
                  "10.0.1.1/32 443/tcp",
            ]
  },
 "group:users": {
            "Deny": [
                  "10.0.1.1/32 443/tcp",
            ]
 }
 ```

Its important to note that the most specific rule effectively creates a new rule "bucket", so if you do something like:  
```json
"group:nerds": {
      "Allow": [
            "10.0.0.0/24 443/tcp"
      ],
      "Deny": [
            "10.0.0.5/32 22/tcp"
      ]
}
```
  
Your clients will not be able to access `10.0.0.5/32 443/tcp`, as the only rule in the `/32` "bucket" is a deny rule. You can solve this by adding the following:
```json
"group:nerds": {
      "Allow": [
            "10.0.0.0/24 443/tcp"
            "10.0.0.5/32 22/tcp"
      ],
      "Deny": [
            "10.0.0.5/32 22/tcp"
      ]
}
```
  
or  
  
```json
"group:nerds": {
      "Allow": [
            "10.0.0.0/24 443/tcp"
      ],
      "Deny": [
            "10.0.0.0/24 22/tcp"
      ]
}
```
As then you're adding the deny rule to the `/24` "bucket".  
  
Additionally, It is possible to define what services a user can access by defining port and protocol rules.  
Currently 3 types of port and protocol rules are supported:  
  
### Any 

When no other rules are defined or the `any` keyword is used wag will allow all services and port combinations.

Example: 

```sh
"1.1.1.1": Allows all ports and protocols to 1.1.1.1/32
"1.1.1.1 54/any": Allows both tcp and udp to 1.1.1.1/32
```

### Single Service

Example:
```sh
192.168.1.1 22/tcp 53/udp: Fairly self explanatory, allows you to hit 22/tcp and 53/udp on a host
1.1.1.1 icmp: As icmp doesnt have ports really you dont need it either
```

### Ranges
You can also define a range of ports with a protocol. wag requires that the lower port is first. 

Example:
```sh
192.168.1.1 22-1024/tcp 23-53/any: Format is low port-high port/service
```


# Limitations
- Only supports clients with one `AllowedIP`, which is perfect for site to site, or client -> server based architecture.  
- Primarily Linux only but windows may work with some effort


# Development 

## Running vite

```sh
export DEV_API_URL=http://127.0.0.1:4433
make debug
sudo ./wag start -config docker-test-config.json
```

## Testing
```sh
cd internal/router
sudo go test -v .
```

## External contributions

If you're looking to add your own features, or bug fixes to wag (thank you!). Please make sure that you've written a test for your changes if possible.  
There are a few `_test.go` files around that give example on how to do this.  

Then open a pull request and we can discuss it there.  

# Donations and Support
If you like `wag` and use it to support your work flow, consider donating to the project. Your donations go directly towards the time and effort I put in, and the amount of support I can provide. 

You can do this by either using the `Support` button on the side or the cryptocurrency wallets detailed below.
  
Monero (XMR):  
`8A8TRqsBKpMMabvt5RxMhCFWcuCSZqGV5L849XQndZB4bcbgkenH8KWJUXinYbF6ySGBznLsunrd1WA8YNPiejGp3FFfPND`  
  
Bitcoin (BTC):  
`bc1qm9e9sfrm7l7tnq982nrm6khnsfdlay07h0dxfr`  
