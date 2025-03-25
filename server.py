import socket
import threading
import json
import os
import time

class Server:
    """
    A multi-client chat server with 2-fault tolerance and data replication.
    """
    def __init__(self, host, port, is_primary=False, is_rejoin=False):
        """
        Initialize the Server instance with configuration and start necessary background threads.
        
        Args:
            host (str): The IP address to bind the server to.
            port (int): The port to listen on.
            is_primary (bool, optional): Whether this server starts as the primary (leader). Defaults to False.
            is_rejoin (bool, optional): Whether this server is rejoining the network. Defaults to False.
        """
        self.host = host
        self.port = port
        self.leader = is_primary
        self.datafile = f"accounts_{self.port}.json"
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.accounts = self.load_accounts() # retrieve account information
        self.lock = threading.Lock()
        self.backup_servers = self.get_backup_servers() # retrieve information of peer servers
        # retrieve inforamtion of leader server
        self.leader_host = self.host if is_primary else self.backup_servers[0]['host']
        self.leader_port = self.port if is_primary else self.backup_servers[0]['port']
        if is_rejoin:
            self.get_leader(self.host, self.port) # retrieve inforamtion of leader server if the server is rejoining
        self.heartbeat_interval = 0.5  # seconds
        self.heartbeat_thread = threading.Thread(target=self.send_heartbeat) # leader server sends heartbeat to backup servers
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()
        self.election_thread = threading.Thread(target=self.monitor_leader) # backup servers send heartbeat to leader server
        self.election_thread.daemon = True
        self.election_thread.start()

    
    def get_backup_servers(self):
        """
        Retrieve the list of backup servers from the configuration file.
        
        Returns:
            list: A list of dictionaries containing host and port information for backup servers.
        """
        import configparser
        config = configparser.ConfigParser()
        config.read('config.ini')
        backups = []
        # store the information of peer servers
        for i in range(1, 4):
            host = config['server'][f'host{i}']
            port = int(config['server'][f'port{i}'])
            if port != self.port: # skip the current server
                backups.append({'host': host, 'port': port})
        return backups
    
    def get_leader(self, rejoin_host, rejoin_port):
        """
        Query backup servers to determine the current leader when rejoining the network.
        
        Args:
            rejoin_host (str): The host address of the rejoining server.
            rejoin_port (int): The port number of the rejoining server.
        """
        count = 0
        for backup in self.backup_servers:
            count += 1
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as backup_socket:
                    backup_socket.connect((backup['host'], backup['port']))
                    # query every server whether it is leader or not
                    backup_socket.send(json.dumps({'action': 'ask_leader', 'host': rejoin_host, 'port': rejoin_port}).encode('utf-8'))
                    response = backup_socket.recv(1024).decode('utf-8')
                    # save the leader information
                    if json.loads(response)['status'] == 'leader':
                        self.leader_host = backup['host']
                        self.leader_port = backup['port']
                        print(f"Found leader: (host: {self.leader_host}, port: {self.leader_port})")
                    count -= 1
                    break
            except:
                continue
        # if the current server is the only alive server, then set itself to be the leader
        if count == len(self.backup_servers):
            self.leader = True
            self.leader_host = self.host
            self.leader_port = self.port
            print("Leader not found, setting self as leader. ")
            print(f"New leader is: (host: {self.leader_host}, port: {self.leader_port})")
    
    def load_accounts(self):
        """
        Loads user accounts from a JSON file.
        
        Returns:
            dict: A dictionary containing user accounts.
        """
        if os.path.exists(self.datafile):
            with open(self.datafile, "r") as file:
                return json.load(file)
        return {}

    def save_accounts(self):
        """
        Saves user accounts to a JSON file.
        """
        with open(self.datafile, "w") as file:
            json.dump(self.accounts, file, indent=4)

    def replicate_data(self, data):
        """
        Replicate account data to all backup servers.
        
        Args:
            data (dict): The account data to be replicated.
        """
        for backup in self.backup_servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as backup_socket:
                    backup_socket.connect((backup['host'], backup['port']))
                    backup_socket.send(json.dumps(data).encode('utf-8'))
            except:
                continue

    def send_heartbeat(self):
        """
        Continuously send heartbeat messages to backup servers if this server is the leader.
        Runs in a separate thread.
        """
        while True:
            if self.leader:
                for backup in self.backup_servers:
                    try:
                        # the leader check if other backup servers are alive
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as backup_socket:
                            backup_socket.connect((backup['host'], backup['port']))
                            backup_socket.send(json.dumps({'action': 'heartbeat'}).encode('utf-8'))
                    except:
                        continue
            time.sleep(self.heartbeat_interval)

    def monitor_leader(self):
        """
        Continuously monitor the leader's status and initiate election if leader is unresponsive.
        Runs in a separate thread.
        """
        while True:
            if not self.leader:
                try:
                    # check if the leader server is alive
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as primary_socket:
                        primary_socket.connect((self.leader_host, self.leader_port))
                        primary_socket.send(json.dumps({'action': 'heartbeat'}).encode('utf-8'))
                        response = primary_socket.recv(1024).decode('utf-8')
                        # initiate leader election if fail to get response from the current leader
                        if json.loads(response)['status'] != 'ack':
                            self.initiate_election()
                except:
                    self.initiate_election()
            time.sleep(self.heartbeat_interval)

    def initiate_election(self):
        """
        Initiate a leader election process.
        The server with the smallest port number becomes the new leader.
        """
        print(f"Server {self.port} initiating election.")
        count = 0
        for backup in self.backup_servers:
            count += 1
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as backup_socket:
                    backup_socket.connect((backup['host'], backup['port']))
                    # if the current server has smaller port number than the other alive server, then set itself to be the leader
                    if backup['port'] > self.port:
                        self.leader = True
                        self.leader_host = self.host
                        self.leader_port = self.port
                        backup_socket.send(json.dumps({'action': 'new_leader', 'host': self.host, 'port': self.port}).encode('utf-8'))
                        print(f"New leader is: (host: {self.leader_host}, port: {self.leader_port})")
                    count -= 1
            except:
                continue
        # if the current server is the only alive server, then set itself to be the leader
        if count == len(self.backup_servers):
            self.leader = True
            self.leader_host = self.host
            self.leader_port = self.port
            print(f"New leader is: (host: {self.leader_host}, port: {self.leader_port})")

    def handle_client(self, client):
        """
        Handles communication among servers or with a connected client.
        
        Args:
            client (socket): The client socket.
        """
        while True:
            message = client.recv(1024).decode('utf-8')
            if not message: # check if there is message
                client.close()
                return
            data = json.loads(message)

            # Handle different operations among servers
            # Heartbeat check
            if data['action'] == 'heartbeat':
                client.send(json.dumps({'status': 'ack'}).encode('utf-8'))
                client.close()
                return

            # Send the information of new leader to backup servers
            if data['action'] == 'new_leader':
                self.leader_host = data['host']
                self.leader_port = data['port']
                print(f"New leader is: (host: {self.leader_host}, port: {self.leader_port})")
                client.close()
                return

            # Check whether the server is leader
            if data['action'] == 'ask_leader':
                if self.leader:
                    client.send(json.dumps({'status': 'leader'}).encode('utf-8'))
                    self.replicate_data({'action': 'update_accounts', 'accounts': self.accounts})
                else:
                    client.send(json.dumps({'status': 'not_leader'}).encode('utf-8'))
                client.close()
                return
            
            # Update account information across servers
            if data['action'] == 'update_accounts':
                with self.lock:
                    self.accounts = data['accounts']
                    self.save_accounts()
                client.close()
                return

            # Handle different operations with a connected client
            # Login
            if data['action'] == 'login':
                username = data['username']
                password = data['password']
                if username in self.accounts: # check if account  exists
                    if self.accounts[username]['password'] == password: # check if password correct
                        client.send(json.dumps({'status': 'success'}).encode('utf-8'))
                    else:
                        client.send(json.dumps({'status': 'failure'}).encode('utf-8'))
                else: # if account does not exist, create new account
                    self.accounts[username] = {'password': password, 'read_messages': [], 'unread_messages': []}
                    self.save_accounts()
                    self.replicate_data({'action': 'update_accounts', 'accounts': self.accounts})
                    client.send(json.dumps({'status': 'success', 'unread_messages': []}).encode('utf-8'))

            # Send a message
            elif data['action'] == 'send':
                recipient = data['recipient']
                if recipient in self.accounts: # check if recipient is a valid account
                    # save message to recipient's undelivered messages
                    self.accounts[recipient]['unread_messages'].append({"from": data['sender'], "message": data['message']})
                    self.save_accounts()
                    self.replicate_data({'action': 'update_accounts', 'accounts': self.accounts})
                    client.send(json.dumps({'status': 'success', 'message': 'Send message successfully.'}).encode('utf-8'))
                else:
                    client.send(json.dumps({'status': 'failure', 'message': 'Invalid recipient. Please enter a valid username.'}).encode('utf-8'))

            # Read unread (undelivered) messaages
            elif data['action'] == 'read_unread':
                username = data['username']
                per_page = data['per_page'] # the number of messages user wants to read
                unread_messages = self.accounts[username]['unread_messages'][:per_page]
                # move messages from unread messages to read messages
                self.accounts[username]['read_messages'].extend(unread_messages)
                self.accounts[username]['unread_messages'] = self.accounts[username]['unread_messages'][per_page:]
                self.save_accounts()
                self.replicate_data({'action': 'update_accounts', 'accounts': self.accounts})
                client.send(json.dumps({'status': 'success', 'messages': unread_messages}).encode('utf-8'))

            # Read all (delivered) messages
            elif data['action'] == 'read_all':
                username = data['username']
                messages = self.accounts[username]['read_messages']
                client.send(json.dumps({'status': 'success', 'messages': messages}).encode('utf-8'))

            # Count unread messages
            elif data['action'] == "count_unread":
                username = data['username']
                client.send(json.dumps({'status': 'success', 'unread_messages': self.accounts[username]['unread_messages']}).encode('utf-8'))

            # List accounts
            elif data['action'] == "list":
                query = data['query'].lower() # query for searching accounts
                accounts = list(self.accounts.keys())
                searched_accounts = [acc for acc in accounts if query in acc.lower()] # accounts that contain query
                client.send(json.dumps({'status': 'success', 'list_accounts': searched_accounts}).encode('utf-8'))

            # Delete message
            elif data['action'] == "delete_message":
                username = data['username']
                idx = data['idx'] # index of message the user wants to delete
                del self.accounts[username]["read_messages"][idx] # delete message
                self.save_accounts()
                self.replicate_data({'action': 'update_accounts', 'accounts': self.accounts})
                client.send(json.dumps({'status': 'success'}).encode('utf-8'))

            # Delete account
            elif data['action'] == "delete_account":
                username = data['username']
                # delete all messages sent from this accounts, so that the recipients will no longer see these messages
                for user in self.accounts:
                    i_un = len(self.accounts[user]['unread_messages'])-1
                    for un_m in self.accounts[user]['unread_messages'][::-1]:
                        if un_m['from'] == username:
                            del self.accounts[user]['unread_messages'][i_un]
                        i_un -= 1
                    i_r = len(self.accounts[user]['read_messages'])-1
                    for r_m in self.accounts[user]['read_messages'][::-1]:
                        if r_m['from'] == username:
                            del self.accounts[user]['read_messages'][i_r]
                        i_r -= 1
                del self.accounts[username] # delete account
                self.save_accounts()
                self.replicate_data({'action': 'update_accounts', 'accounts': self.accounts})
                client.send(json.dumps({'status': 'success'}).encode('utf-8'))

    def start(self):
        """
        Starts the server and listens for incoming client connections.
        """
        while True:
            client, address = self.server.accept()
            print(f"Connected with {str(address)}")
            threading.Thread(target=self.handle_client, args=(client,)).start()

    def stop(self):
        self.running = False
        self.server.close()

if __name__ == "__main__":
    import argparse

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Start the chat server.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="The host address to bind the server to.")
    parser.add_argument("--port", type=int, required=True, help="The port to bind the server to.")
    parser.add_argument("--primary", action="store_true", help="Set this server as the primary server.")
    parser.add_argument("--rejoin", action="store_true", help="Rejoin the server.")
    args = parser.parse_args()

    # Start the server
    server = Server(args.host, args.port, is_primary=args.primary, is_rejoin=args.rejoin)
    server.start()