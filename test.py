import unittest
import threading
import time
import client
import server
import socket

class TestClientServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Start multiple servers in separate threads before running any tests."""
        cls.servers = []
        cls.server_threads = []

        # Start primary server
        cls.primary_server = server.Server(host='127.0.0.1', port=5555, is_primary=True)
        cls.servers.append(cls.primary_server)
        cls.server_threads.append(threading.Thread(target=cls.primary_server.start))
        cls.server_threads[-1].daemon = True
        cls.server_threads[-1].start()

        # Start backup servers
        cls.backup_server1 = server.Server(host='127.0.0.1', port=5556)
        cls.servers.append(cls.backup_server1)
        cls.server_threads.append(threading.Thread(target=cls.backup_server1.start))
        cls.server_threads[-1].daemon = True
        cls.server_threads[-1].start()

        cls.backup_server2 = server.Server(host='127.0.0.1', port=5557)
        cls.servers.append(cls.backup_server2)
        cls.server_threads.append(threading.Thread(target=cls.backup_server2.start))
        cls.server_threads[-1].daemon = True
        cls.server_threads[-1].start()

        # Wait for servers to start
        time.sleep(2)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests are done."""
        for server_instance in cls.servers:
            try:
                server_instance.server.close()
            except Exception as e:
                print(f"Error closing server socket: {e}")

    def setUp(self):
        """Initialize the client for each test."""
        self.client = client.Client(hosts=[
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])

    def test_server_creation(self):
        """Test that the servers are created correctly."""
        for server_instance in self.servers:
            self.assertIsInstance(server_instance, server.Server)
            self.assertEqual(server_instance.host, '127.0.0.1')
            self.assertIn(server_instance.port, [5555, 5556, 5557])
            self.assertIsNotNone(server_instance.server)

    def test_server_listening(self):
        """Test that the servers are listening for connections."""
        test_client = client.Client(hosts=[
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])
        self.assertIsNotNone(test_client.client)
        connected_port = test_client.client.getpeername()[1]
        self.assertIn(connected_port, [5555, 5556, 5557])

    def test_client_creation(self):
        """Test that the client is created correctly."""
        self.assertIsInstance(self.client, client.Client)
        self.assertEqual(self.client.hosts, [
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])
        self.assertIsNotNone(self.client.client)

    def test_client_connection(self):
        """Test that the client can connect to one of the servers."""
        self.assertIsNotNone(self.client.client)
        peer_address = self.client.client.getpeername()
        self.assertEqual(peer_address[0], '127.0.0.1')
        self.assertIn(peer_address[1], [5555, 5556, 5557])

    def test_login_existing_user(self):
        """Test logging in with an existing user."""
        # Add a user to the primary server's accounts
        self.primary_server.accounts = {'existing_user': {'password': 'hashed_password', 'read_messages': [], 'unread_messages': []}}
        result = self.client.login('existing_user', 'hashed_password')
        self.assertTrue(result)

    def test_login_new_user(self):
        """Test signing up a new user."""
        # Ensure the primary server's accounts are empty
        result = self.client.login('new_user', 'hashed_password')
        self.assertTrue(result)

        # Verify by listing accounts through the API
        self.client.username = 'new_user'
        result_list = self.client.list_accounts('new_user')
        self.assertIn('new_user', result_list)

    def test_login_wrong_password(self):
        """Test logging in with a wrong password for an existing user."""
        # Add a user to the primary server's accounts
        self.primary_server.accounts = {'existing_user': {'password': 'hashed_password', 'read_messages': [], 'unread_messages': []}}
        # Attempt to log in with the wrong password
        result = self.client.login('existing_user', 'wrong_password')
        self.assertFalse(result)

    def test_list_accounts(self):
        """Test listing all accounts."""
        self.client.login('user1', 'hashed_password')
        self.client.login('user2', 'hashed_password')
        self.client.login('user3', 'hashed_password')
        
        self.client.username = 'user1'  # Set any logged-in user
        result = self.client.list_accounts('')
        self.assertEqual(result, ['user', 'user1', 'user2', 'user3'])

    def test_list_accounts_with_query(self):
        """Test listing accounts with a search query."""
        self.client.login('user1', 'hashed_password')
        self.client.login('user2', 'hashed_password')
        self.client.login('user3', 'hashed_password')

        self.client.username = 'user1'  # Set any logged-in user
        result = self.client.list_accounts('user2')
        self.assertEqual(result, ['user2'])

    def test_send_message_valid_recipient(self):
        """Test sending a message to a valid recipient."""
        self.client.login('sender', 'hashed_password')
        recipient_client = client.Client(hosts=[
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])
        recipient_client.login('recipient', 'hashed_password')

        self.client.username = 'sender'
        status, result = self.client.send_message('recipient', 'Hello')
        self.assertEqual(status, True)
        self.assertEqual(result, 'Send message successfully.')

    def test_send_message_invalid_recipient(self):
        """Test sending a message to an invalid recipient."""
        self.client.login('sender', 'hashed_password')

        self.client.username = 'sender'
        status, result = self.client.send_message('invalid_recipient', 'Hello')
        self.assertEqual(status, False)
        self.assertEqual(result, 'Invalid recipient. Please enter a valid username.')

    def test_read_unread_messages(self):
        """Test reading unread messages."""
        self.client.login('user', 'hashed_password')
        sender_client = client.Client(hosts=[
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])
        sender_client.login('sender', 'hashed_password')

        # Send the message using the protocol
        sender_client.username = 'sender'
        status, msg = sender_client.send_message('user', 'Hello')
        self.assertTrue(status)

        # Now read unread messages
        self.client.username = 'user'
        result = self.client.read_unread_messages(1)
        self.assertEqual(result, [{'from': 'sender', 'message': 'Hello'}])

    def test_read_all_messages(self):
        """Test reading all messages."""
        self.client.login('user', 'hashed_password')
        sender_client = client.Client(hosts=[
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])
        sender_client.login('sender', 'hashed_password')

        # Send a message
        sender_client.username = 'sender'
        status, msg = sender_client.send_message('user', 'Hello')
        self.assertTrue(status)

        self.client.username = 'user'
        _ = self.client.read_unread_messages(1)
        result = self.client.read_messages()
        self.assertEqual(result, [{'from': 'sender', 'message': 'Hello'}])

    def test_delete_message(self):
        """Test deleting a message."""
        self.primary_server.accounts = {
            'user': {'password': '123', 'unread_messages': [], 'read_messages': [{'from': 'sender', 'message': 'Hello'}]}
        }
        self.client.username = 'user'
        result = self.client.delete_message('sender', 'Hello', 0)
        self.assertEqual(result, True)
    
    def test_delete_account(self):
        """Test deleting an account."""
        self.primary_server.accounts = {
            'user': {'password': '123', 'unread_messages': [], 'read_messages': []},
            'other_user': {'password': '123', 'read_messages': [], 'unread_messages': [{'from': 'user', 'message': 'Hello'}]}
        }
        self.client.username = 'user'
        result = self.client.delete_account()
        self.assertEqual(result, True)
        self.assertNotIn('user', self.primary_server.accounts)
        self.assertEqual(self.primary_server.accounts['other_user']['unread_messages'], [])
    
    def test_fault_tolerance_one_server_down(self):
        """Test the system's ability to handle one server failure."""
        # Shut down the primary server
        self.primary_server.server.close()
        time.sleep(1)  # Wait for the system to detect the failure

        # Ensure the client can still connect and perform operations
        self.client = client.Client(hosts=[
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])
        self.assertTrue(self.client.login('user', '123'))

    def test_fault_tolerance_two_servers_down(self):
        """Test the system's ability to handle two server failures."""
        # Shut down the primary server and one backup server
        self.primary_server.server.close()
        self.backup_server1.server.close()
        time.sleep(1)  # Wait for the system to detect the failures

        # Ensure the client can still connect and perform operations
        self.client = client.Client(hosts=[
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])
        self.assertTrue(self.client.login('user', '123'))


    def test_leader_election(self):
        """Test that a new leader is elected when the primary server fails."""
        # Shut down the primary server
        self.primary_server.server.close()
        time.sleep(2)  # Wait for leader election to complete

        # Check if a new leader has been elected
        new_leader = None
        for server_instance in self.servers[1:]:
            if server_instance.leader:
                new_leader = server_instance
                break
        self.assertIsNotNone(new_leader)
        self.assertEqual(new_leader.port, 5556)  # The new leader should not be the primary server

    def test_data_consistency(self):
        """Test that data is consistent across all servers."""
        # Create a new user
        new_client2 = client.Client(hosts=[
            {'host': '127.0.0.1', 'port': 5555},
            {'host': '127.0.0.1', 'port': 5556},
            {'host': '127.0.0.1', 'port': 5557}
        ])
        new_client2.login('new_client2', '123')
        time.sleep(1)  # Wait for replication

        # Check that the user exists on all servers
        for server_instance in self.servers:
            self.assertIn('new_client2', server_instance.accounts)

if __name__ == '__main__':
    unittest.main()