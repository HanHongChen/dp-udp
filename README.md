# Dual-Path UDP (dp-udp)

**Dual Path UDP**: A layer 5 application implementing dual-path UDP with iperf3 sequence number deduplication.

Dual-Path here means packets are transmitted over two separate UDP connections for redundancy and increased throughput, with deduplication using iperf3 sequence numbers.

## Features

- **Dual-Path UDP**: Utilizes two separate UDP connections for redundancy and increased throughput
- **iperf3 Compatible**: Uses iperf3 UDP packet format with sequence numbers for packet ordering and deduplication
- **Packet Deduplication**: Duplicate packet detection using iperf3 sequence numbers
- **Out-of-Order Detection**: Identifies and handles out-of-order packets
- **Tunnel Interface**: Creates and manages TUN devices for transparent packet routing

## Description

As dp-udp starts, it creates a network interface to proxy real data packets. In the above image, packets from the blue network interface to the green network interface undergo packet duplication, while packets from the green network interface to the blue network interface undergo packet deduplication.

### Packet Format

The application uses iperf3-compatible UDP packet format:

```
| Timestamp (sec) | Timestamp (usec) | Sequence Number | Payload |
|     4 bytes     |      4 bytes     |     4 bytes     |   ...   |
```

### Deduplication Logic

Unlike the original TCP version that used hash-based deduplication, dp-udp uses iperf3 sequence numbers for:

1. **Duplicate Detection**: Tracks seen sequence numbers to filter duplicate packets
2. **Out-of-Order Handling**: Manages packets arriving out of sequence
3. **Gap Detection**: Identifies lost packets based on sequence number gaps
4. **Statistics**: Provides detailed packet statistics including duplicates, out-of-order, and lost packets

## Usage

### Building

```bash
git clone git@github.com:HanHongChen/dp-udp.git
cd dp-udp
go build -o dp-udp
```

### Running Server

```bash
sudo ./dp-udp server -c config/server_udp.yaml
```

### Running Client

```bash
sudo ./dp-udp client -c config/client_udp.yaml
```

**Note**: Root privileges are required for TUN device creation and management.

After starting, users can use the created network interface for their applications. The application will handle routing automatically based on the configuration.

## Quickstart

1. Clone and make

    ```bash
    git clone git@github.com:Alonza0314/dp-tcp.git
    cd dp-tcp
    make
    ```

2. Start and enter namespace

    - Start

        ```bash
        ./namespace.sh up
        ```

    - Server-ns

        ```bash
        ./namespace.sh server-ns

        # after enter namespace
        ./build/dp-tcp server -c config/server.yaml
        ```

    - Client-ns

        ```bash
        ./namespace.sh client-ns

        # after enter namespace
        ./build/dp-tcp client -c config/client.yaml
        ```

    - Demo

        ![dp-tcp](/images/dp-tcp.png)

3. ncat test

    - Server

        ```bash
        ncat -u -l 10.0.0.1 9999
        ```

    - Client

        ```bash
        ncat -u --source 10.0.0.2 10.0.0.1 9999
        ```

    - Demo

        ![ncat](./images/ncat.png)

## Appendix

- "github.com/songgao/water": used to bring up network device.
- "github.com/cornelk/hashmap": safe concurrent map.
- "github.com/cespare/xxhash/v2": quick hash for operating packet hashing
