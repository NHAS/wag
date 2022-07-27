# Wag

Wag adds 2fa to wireguard.    
It allows you to restrict routes based on 2fa, while allowing other routes to remain public as long as a client has a valid public key.  

# Requirements

The wireguard device must be running before wag is started.  
  
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

# Limitations
- Only supports clients with one `AllowedIP`, which is perfect for site to site, or client -> server based architecture.  
- IPv4 only.
- Linux only
