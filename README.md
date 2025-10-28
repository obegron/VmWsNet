# VmWsNet

A WebSocket based VPN/proxy relay for virtual machines.

## Features

- **Secure Communication:** Supports secure WebSockets (WSS) for encrypted data transfer.
- **Dynamic IP Allocation:** Built-in DHCP-like server to automatically assign IP addresses to virtual machines.
- **VM-to-VM Networking:** Allows virtual machines on the same relay to communicate with each other (configurable).
- **Admin Interface:** A web-based UI to monitor active sessions and manage proxy rules.
- **HTTP Proxying:** Reverse proxy functionality to expose services from VMs to the host network.
- **Rate Limiting:** Configurable bandwidth limits for each connected VM.

## How to use

### 1. Installation

This project requires Node.js. You also need to install the `ws` dependency.

```bash
npm install ws
```

### 2. Generating SSL/TLS key pair (for WSS)

For secure WebSockets (WSS), you need to generate a private key and a certificate. You can generate a self-signed pair using OpenSSL:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

This will create `key.pem` and `cert.pem` in your project directory. When prompted, you can leave the fields for distinguished name blank.

### 3. Running the relay

Once the dependencies are installed and you have your key pair (if using WSS), you can start the relay server:

```bash
node relay.js
```

The server will start, and you can see log output in your console.

### 4. Admin UI

The project includes a simple web-based admin UI. By default, it's available at `http://localhost:8001`.
