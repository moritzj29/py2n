# Py2N

<img src="https://user-images.githubusercontent.com/38865194/210242643-8f2cef4d-e426-4280-9263-63bee2b66eef.png" width=20% height=20%>

Asynchronous library to control [2N Telekomunikace® devices](https://www.2n.com)

**This library is under development**

## Requirements

- Python >= 3.9
- aiohttp

## Install
```bash
pip install py2n
```

## Configuration of 2N device
Required HTTP API services for the library to work:
- System API
- Switch API
- I/O API
- Logging API

For each service
- enabled needs to be ticked
- connection type needs to match protocol (unsecure (TCP) -> HTTP, secure (TLS) -> HTTPS); unsecure allows both HTTP and HTTPS connections
- authentication can be set to either Basic Auth or Digest Auth (no mixing), the corresponding flag needs to be set when the connection is established

Account with following user privileges (at least monitoring) needs to enabled:
- System
- Inputs and Outputs
- Switches

Since Basic Auth transmits credentials in plain text, it is highly recommended to use HTTPS protocol (even with default self-signed certificates).

## Example

```python
from py2n import Py2NDevice, Py2NConnectionData

import asyncio
import aiohttp

async def main():
    """Run with aiohttp ClientSession."""
    async with aiohttp.ClientSession() as session:
        await run(session)


async def run(websession):
    """Use library."""
    device = await Py2NDevice.create(
        websession,
        Py2NConnectionData(
            host="192.168.1.69",
            username="username",
            password="password",
            # auth_method="digest", # default: "basic"
            # protocol="https", # default: "http"
            # ssl_verify=True, # default: False
        ),
    )

    await device.restart()

asyncio.run(main())
```

`auth_method` controls HTTP auth scheme and supports `"basic"` (default) and `"digest"`. 2N recommends Digest Auth, especially if using plain HTTP instead of HTTPS.
`ssl_verify` controls TLS certificate verification for HTTPS connections. Requires the device to present a trusted server certificate (e.g. Let's Encrypt).

