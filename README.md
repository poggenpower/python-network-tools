# Python Network Tools and Servers

repository for various network servers and tools written in Python.

All tested with python >= 3.9. There is no intend to support older versions.

PRs and questions are welcome.

## UDP Relay
file: `udp_relay2.py`

Relaying a UDP connection from one host/port to another. E.g. to make your VPN available behind CGN.

### Features
- IPv6 and IPv4 support and all combinations
- DNS resolution for every new client connection e.g. if the destination uses dyn dns
- Support for multiple clients simultaneously 

### TODO
- Command line switch to enable debug logging
- Better code documentation

### Usage
```
❯ python3 udp_relay2.py --help
usage: udp_relay2.py [-h] [-l LOCAL_PORT] [-H REMOTE_HOST] [-r REMOTE_PORT]

optional arguments:
  -h, --help            show this help message and exit
  -l LOCAL_PORT, --local-port LOCAL_PORT
  -H REMOTE_HOST, --remote-host REMOTE_HOST
  -r REMOTE_PORT, --remote-port REMOTE_PORT
  ```

### inspired by / similar projects

https://github.com/wangyu-/tinyPortMapper written in C++ but no DNS support
https://github.com/EtiennePerot/misc-scripts/blob/master/udp-relay.py no IPv6 support 

## Fake TLS Echo Server / Client
TLS Server with SNI support. Generates X509 Certificates with proper SAN (Subject Alternative Names) on the fly.
Echos back the input string in a JSON wrapper

Client send string to TLS Server. Send proper SNI and logs response.

[TODO: Upload initial version]


## Fake DNS Server
DNS Server to fake DNS answers. E.g. answer all requests with the same IP, but specific overwrites and different "no answers"

[TODO: Upload initial version]

## Temp PKI
Generating X509 Certificates and Keys on the fly to enable TLS support for fake servers 

[TODO: Upload initial version]