# web-server

This is a C++ project that implements a reliable byte-stream transport over UDP and
a small encrypted key-value server on top of it. Everything runs in Docker, but it also builds on Linux.

## Files

- `lib/` contains the transport library: the sender, the receiver and the shared `poll`
  helper.
- `server.cpp` keeps the key-value database, parses the commands and answers the clients.
- `client.cpp` connects to the server and sends the commands read from stdin.
- `crypto.cpp` and `crypto.h` contain the X25519 key exchange and the AES-256-GCM helpers.
- `demo.sh` runs a visible walkthrough of all the database commands.
- `Dockerfile` and `docker-compose.yml` build and run everything in Docker.

## Features

- A reliable transport over UDP: three-way handshake, sliding window with cumulative ACKs,
  flow control, timeouts and retransmission.
- A temporary key-value database kept in RAM. It is shared by all connected clients and is
  lost when the server stops.
- The commands `set`, `get`, `delete` and `print`.
- An encrypted channel for every connection. I used X25519 for the key exchange and
  AES-256-GCM for the data, so commands and responses are encrypted and authenticated.
- Multiple clients at the same time. Each connection has its own reader thread and its own
  encryption keys.
- A Docker image and a Compose file, so the project can be built and played with without
  installing the Linux toolchain on the host.

## Commands

| Command | What it does |
| --- | --- |
| `set <key> <value>` | Adds the key or updates its value. Returns `OK`. |
| `get <key>` | Returns the value, or `(nil)` if the key does not exist. |
| `delete <key>` | Removes the key. Returns `OK`, or `(nil)` if it did not exist. |
| `print` | Returns every pair as `key = value`, sorted by key. An empty store returns `(empty)`. |

A key is a single token. The value is the rest of the line, so it can contain spaces.

## How to use it

### Docker

I build one image that contains both binaries. The default command starts the server:

```bash
docker build -t web-server .
```

```bash
docker run --rm -p 8032:8032/udp web-server
```

To see the features in action, run the demo. It starts its own server inside the container and
prints every command with the response:

```bash
docker run --rm web-server ./demo.sh
```

The output looks like this:

```text
web-server key-value store
=========================

Each command below opens a new encrypted client connection; the store is shared.

db> set name John
OK

db> get name
John

db> set name John Brown
OK

db> get name
John Brown

db> set city London
OK

db> print
city = London
name = John Brown

db> delete name
OK

db> get name
(nil)

db> print
city = London

db> get missing
(nil)

demo complete
```

The demo opens a new client connection for every command. This shows that the store is shared
between connections and that every connection does its own key exchange.

### Docker Compose

I also added a Compose file with three services: `server`, `client` and `demo`. Build the image
once, then start the server:

```bash
docker compose build
```

```bash
docker compose up -d server
```

The client service connects to the server by its Compose name:

```bash
docker compose run --rm client
```

The demo service runs the same walkthrough as before:

```bash
docker compose run --rm demo
```

### Local build

The transport uses `timerfd`, so it only builds on Linux. The crypto module also needs the
OpenSSL headers (`libssl-dev` on Debian/Ubuntu); inside the Docker image they are already
installed.

```bash
make
```

Start the server and then the client:

```bash
./server
```

```bash
./client
```

The client accepts a hostname or an IP address, so `./client 127.0.0.1 8032` works locally and
`./client server 8032` works on the Compose network. I can also pipe the commands in; the
client waits for one response per command:

```bash
printf 'set city London\nget city\nprint\n' | ./client 127.0.0.1 8032
```

### Options

```
./server [recv_buffer_bytes]
./client [host] [port] [speed_mbps] [delay_ms]
```

`recv_buffer_bytes` defaults to the 64 KiB backing array. `speed_mbps` and `delay_ms` default
to `10` and `2`; they only set the BDP-derived window and the retransmit timeout, they do not
throttle the send rate.

## How it works

### The transport

The library in `lib/` implements the three-way handshake, the sliding window with cumulative
ACKs, the flow control and the retransmissions. The receiver advertises its free space, and the
sender retransmits the whole in-flight window when a timer expires. One background handler
thread per side multiplexes all the connections with `poll`.

### The database

`server.cpp` keeps a `std::map<std::string, std::string>` protected by `db_lock`. Every
connection has its own reader thread, and all of them use the same map. `set` adds a key or
updates its value, `get` returns the value or `(nil)`, `delete` removes the key, and `print`
returns all the pairs sorted by key.

### The encrypted channel

When a client connects, both sides generate an ephemeral X25519 key pair. The client sends its
public key with `KEY <hex>`; the server answers with its own public key on the reply port. Both
sides derive two keys with HKDF-SHA256, one for each direction, and use them with AES-256-GCM.
Each message is framed as `[2-byte length][12-byte nonce][ciphertext][16-byte tag]`. The
transport headers stay plaintext; the commands and responses are encrypted.

I did not authenticate the X25519 exchange, so an active man-in-the-middle could substitute the
public keys. The encryption protects against passive eavesdropping; a real deployment should
use TLS or a signed long-term key.

### Responses

The transport only sends data from the client to the server, so I added a separate UDP socket
for responses. The client registers its port with `REGISTER <port>`, and the server sends the
encrypted responses there with `send_response`. This keeps the responses out of the sender's
ACK path.

## Notes

- There is no user authentication or access control. Anyone who can reach UDP 8032 can use
  the store, so this is a demo service and should not be exposed to the public internet.
- Command lines are limited to 1023 characters. Responses are one UDP datagram per command,
  capped at 8 KiB.
- The client waits up to two seconds for a response.
- The database is RAM-only and is not persisted.
- The `print` output is sorted because the store is a `std::map`.
