# Fault-Tolerant Chat Application
This project is a distributed client-server chat application designed with **2-fault tolerance** and **data replication** implemented with Python. The application allows users to sign up, log in, send and receive messages, delete messages, search for other users, and manage their accounts. The client is built with a graphical interface using tkinter, and the system supports multiple clients via multithreading. The system uses **JSON** as the wire protocol for client-server communication. 

Key Features:
- **2-Fault Tolerance:** The system is initialized with three servers and continues operating even if up to two servers fail.
- **Server Rejoin:** Servers that go down can rejoin the network and synchronize their data with the current leader without disrupting the ongoing client operations.
- **Data Replication:** All operations are replicated across backup servers, ensuring data consistency and availability.

## Running the System
To run the system, make sure the server side machines have files `server.py` and `config.ini`, and the client side machines have files `client.py` and `config.ini`.
### 1. Start the Three Servers
Run the following 3 commands each in a separate terminal:
```sh
python server.py --host {server1_host} --port 5555 --primary
python server.py --host {server2_host} --port 5556
python server.py --host {server3_host} --port 5557
```

#### Example
Here is how you can run the system on a single machine, but you can run it across multiple machines by modifying the server IPs accordingly. 

```sh
python server.py --host 127.0.0.1 --port 5555 --primary
python server.py --host 127.0.0.1 --port 5556
python server.py --host 127.0.0.1 --port 5557
```

### 2. Modify Config File
Modify `config.ini` to store the server configurations.

#### Example
```sh
[server]
host1 = 127.0.0.1
port1 = 5555
host2 = 127.0.0.1
port2 = 5556
host3 = 127.0.0.1
port3 = 5557
```
### 3. Run the Client
Run the following command in a separate terminal (different from the server terminals):
```sh
python client.py
```

### 4. Rejoin a Server
If a server goes down, rejoin it using the `--rejoin` flag.
```sh
python server.py --host {rejoin_server_host} --port {rejoin_server_port} --rejoin
```

#### Example
```sh
python server.py --host 127.0.0.1 --port 5555 --rejoin
```
The rejoining server will find the leader and fetch the latest data from the leader. 

## File Structure

```sh
.
├── client.py
├── server.py
├── config.ini
├── test.py
```

### `client.py`
- Implements the **Client** class, which connects to one of the servers and facilitates communication.
- Provides methods for logging in, creating new accounts, managing user authentication, sending messages, reading messages, deleting messages, searching for existing accounts, and deleting accounts. 
- Implements the **ChatApp** class, which provides a `tkinter` GUI and defines the logic for user interactions.
- Built-in reconnection logic if the server connection is lost. 

### `server.py`
- Implements the **Server** class, which implements server interactions for 2-fault tolerance and data consistency, as well as client-side requests for user operations.
- Manages client requests for account creation, user authentication, account retrieval, message delivery, message retrieval, message deletion, and account deletion.
- For each of the servers, stores user data in a JSON file (`accounts_{server_port}.json`).
- Handles data replication to backup servers, heartbeat mechanism, leader monitoring, leader election when the leader fails, and rejoin mechanism that allows a crashed server to sync back.

### `config.ini`
Stores hosts and ports information for all servers. Used by both `client.py` and `server.py` to facilicate client-server connection. 

### `test.py`
- Contains **unit tests** for the client-server interaction using Python’s unittest module.
- System initialization tests: multiple server creation, client creation, client-server communication.
- User operation tests: user account creation and authentication, account search, message view and delivery, and account deletion.
- Fault tolerance and replication tests: one-fault tolerance, two-fault tolerance, client reconnection, leader election, data consistency. 