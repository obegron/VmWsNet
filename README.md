# RootlessRelay

A WebSocket based VPN/proxy relay for virtual machines.

## Features

- **Secure Communication:** Supports secure WebSockets (WSS) for encrypted data transfer.
- **Dynamic IP Allocation:** Built-in DHCP-like server to automatically assign IP addresses to virtual machines.
- **VM-to-VM Networking:** Allows virtual machines on the same relay to communicate with each other (configurable).
- **Admin Interface:** A web-based UI to monitor active sessions and manage proxy rules.
- **HTTP Proxying:** Reverse proxy functionality to expose services from VMs to the host network.
- **Rate Limiting:** Configurable bandwidth limits for each connected VM.

## Configuration

All configuration is done by editing the constants at the top of the `relay.js` file.

### Basic Settings

| Setting                  | Purpose                                                                | Default |
| ------------------------ | ---------------------------------------------------------------------- | ------- |
| `ENABLE_DEBUG`           | Enable verbose debug logging to the console.                           | `false` |
| `RATE_LIMIT_KBPS`        | Maximum upload/download bandwidth for each VM in kilobytes per second. | `1024`  |
| `MAX_CONNECTIONS_PER_IP` | Maximum number of concurrent WebSocket connections from a single IP.   | `4`     |
| `ENABLE_WSS`             | Use Secure WebSockets (WSS). Requires `cert.pem` and `key.pem`.        | `true`  |
| `ENABLE_VM_TO_VM`        | Allow VMs on the same relay to communicate with each other.            | `true`  |

### Advanced Settings

| Setting           | Purpose                                                    | Default                    |
| ----------------- | ---------------------------------------------------------- | -------------------------- |
| `GATEWAY_IP`      | IP address of the virtual gateway within the VM's network. | `10.0.2.2`                 |
| `DHCP_START`      | The starting IP address for the DHCP pool (last octet).    | `15`                       |
| `DHCP_END`        | The ending IP address for the DHCP pool (last octet).      | `254`                      |
| `DNS_SERVER_IP`   | DNS server provided to VMs via DHCP.                       | `8.8.8.8`                  |
| `TCP_WINDOW_SIZE` | TCP window size for connections to/from the VM.            | `10240`                    |
| `WS_PORT`         | Port for the WebSocket server.                             | `8443` (WSS) / `8086` (WS) |
| `ADMIN_PORT`      | Port for the web-based admin interface.                    | `8001`                     |
| `PROXY_PORT`      | Port for the HTTP reverse proxy server.                    | `8080`                     |

## How to use

### 1. Installation

This project requires Node.js. You can install the dependencies using npm:

```bash
npm install
```

### 2. Generating SSL/TLS key pair (for WSS)

For secure WebSockets (WSS), you need to generate a private key and a certificate. You can generate a self-signed pair using the following npm script:

```bash
npm run keygen
```

This will create `key.pem` and `cert.pem` in your project directory. When prompted, you can leave the fields for distinguished name blank.

Alternatively, you can run the `openssl` command directly. This is useful if you want to use different settings:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 3. Running the relay

Once the dependencies are installed and you have your key pair (if using WSS), you can start the relay server:

```bash
npm start

```

| In the browser you will use the relay first visit <https://127.0.0.1:8443> and trust the certificate you created.

The server will start, and you can see log output in your console.

### 4. Admin UI

The project includes a simple web-based admin UI. By default, it's available at `http://localhost:8001`.
