import socket
import json
import tkinter as tk
from tkinter import messagebox
import hashlib

class Client:
    """
    A client for a chat application, handling communication with the servers. 
    Built-in reconnection logic if the server connection is lost. 
    """
    def __init__(self, hosts):
        """
        Initialize the Client instance and establish a connection to one of the servers. 
        
        Args:
            hosts (list): A list of dictionaries containing the host and port of servers.
        """
        self.hosts = hosts
        self.client = None
        self.username = None
        self.connect_to_server()

    def connect_to_server(self):
        """
        Attempt to connect to one of the available servers.
        """
        for host in self.hosts:
            try:
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client.connect((host['host'], host['port']))
                print(f"Connected to server at {host['host']}:{host['port']}")
                return  # exit after a successful connection
            except Exception as e:
                print(f"Failed to connect to {host['host']}:{host['port']} - {e}")
                continue
        self.client = None
        print("Failed to connect to any server.")


    def reconnect(self):
        """
        Attempt to reconnect to the servers if the connection is lost.

        Returns:
            bool: True if reconnection was successful, False otherwise.
        """
        print("Attempting to reconnect...")
        for host in self.hosts:
            try:
                new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                new_socket.connect((host['host'], host['port']))
                print(f"Reconnected to server at {host['host']}:{host['port']}")
                self.client = new_socket
                return True
            except Exception as e:
                print(f"Failed to reconnect to {host['host']}:{host['port']} - {e}")
                continue
        return False


    def send_message(self, recipient, message):
        """
        Send a send message request to server and get response. 
        Attempt to reconnect if connection is lost during the operation. 
        
        Args:
            recipient (str): The recipient's username.
            message (str): The message content to be sent. 
        
        Returns:
            tuple: A boolean indicating success, and the server's response message.
        """
        data = {
            'action': 'send',
            'sender': self.username,
            'recipient': recipient,
            'message': message
        }
        try:
            self.client.send(json.dumps(data).encode('utf-8'))
            raw = self.client.recv(1024).decode('utf-8')
            if not raw:
                raise ConnectionResetError("Empty response - possible server down")
            response = json.loads(raw)
            return response['status'] == 'success', response['message']
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            print("Connection lost during send message. Attempting to reconnect...")
            if self.reconnect():
                # Retry send_message once after reconnect
                return self.send_message(recipient, message)
            else:
                print("Failed to reconnect. Send message failed.")
                return False

    def read_unread_messages(self, per_page):
        """
        Send a retrieve unread (undelivered) messages to server and get response.
        Attempt to reconnect if connection is lost during the operation. 
        
        Args:
            per_page (int): The number of messages to retrieve.
        
        Returns:
            list: A list of unread messages, each represented as a dictionary.
        """
        data = {
            'action': 'read_unread',
            'username': self.username,
            'per_page': per_page
        }
        try:
            self.client.send(json.dumps(data).encode('utf-8'))
            raw = self.client.recv(1024).decode('utf-8')
            if not raw:
                raise ConnectionResetError("Empty response - possible server down")
            response = json.loads(raw)
            return response['messages'] if response['status'] == 'success' else []
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            print("Connection lost during read unread messages. Attempting to reconnect...")
            if self.reconnect():
                # Retry read_unread_messages once after reconnect
                return self.read_unread_messages(per_page)
            else:
                print("Failed to reconnect. Read unread messages failed.")
                return False

    def read_messages(self):
        """
        Send a retrieve read (delivered) messages to server and get response.
        Attempt to reconnect if connection is lost during the operation.
        
        Returns:
            list: A list of read messages, each represented as a dictionary.
        """
        data = {
            'action': 'read_all',
            'username': self.username
        }
        try:
            self.client.send(json.dumps(data).encode('utf-8'))
            raw = self.client.recv(1024).decode('utf-8')
            if not raw:
                raise ConnectionResetError("Empty response - possible server down")
            response = json.loads(raw)
            return response['messages'] if response['status'] == 'success' else []
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            print("Connection lost during read messages. Attempting to reconnect...")
            if self.reconnect():
                # Retry read_messages once after reconnect
                return self.read_messages()
            else:
                print("Failed to reconnect. Read messages failed.")
                return False

    def get_unread(self):
        """
        Reqeust to retrieve a list of unread messages for the current user from server and get response. 
        Attempt to reconnect if connection is lost during the operation.
        
        Returns:
            list: A list of unread messages, each represented as a dictionary.
        """
        data = {
            'action': 'count_unread',
            'username': self.username
        }
        try:
            self.client.send(json.dumps(data).encode('utf-8'))
            raw = self.client.recv(1024).decode('utf-8')
            if not raw:
                raise ConnectionResetError("Empty response - possible server down")
            response = json.loads(raw)
            return response['unread_messages'] if response['status'] == 'success' else []
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            print("Connection lost during get unread. Attempting to reconnect...")
            if self.reconnect():
                # Retry get_unread once after reconnect
                return self.get_unread()
            else:
                print("Failed to reconnect. Get unread failed.")
                return False

    def login(self, username, password):
        """
        Request to authenticate the user with the provided credentials and get response from server.
        Attempt to reconnect if connection is lost during the operation.
        
        Args:
            username (str): The username of the account.
            password (str): The password for authentication.
        
        Returns:
            bool: True if login was successful, False otherwise.
        """
        data = {
            'action': 'login',
            'username': username,
            'password': password
        }
        try:
            self.client.send(json.dumps(data).encode('utf-8'))
            raw = self.client.recv(1024).decode('utf-8')
            if not raw:
                raise ConnectionResetError("Empty response - possible server down")
            response = json.loads(raw)
            if response['status'] == 'success':
                self.username = username
                return True
            return False
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            print("Connection lost during login. Attempting to reconnect...")
            if self.reconnect():
                # Retry login once after reconnect
                return self.login(username, password)
            else:
                print("Failed to reconnect. Login failed.")
                return False


    def list_accounts(self, query):
        """
        Request to retrieve a list of accounts that match the query from server and get response. 
        Attempt to reconnect if connection is lost during the operation.
        
        Args:
            query (str): The search query to filter accounts.
        
        Returns:
            list: A list of usernames matching the query, or an error message if the operation fails.
        """
        data = {
            'action': 'list',
            'username': self.username,
            'query': query
        }
        try:
            self.client.send(json.dumps(data).encode('utf-8'))
            raw = self.client.recv(1024).decode('utf-8')
            if not raw:
                raise ConnectionResetError("Empty response - possible server down")
            response = json.loads(raw)
            return response['list_accounts'] if response['status'] == 'success' else []
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            print("Connection lost during list accounts. Attempting to reconnect...")
            if self.reconnect():
                # Retry list_accounts once after reconnect
                return self.list_accounts(query)
            else:
                print("Failed to reconnect. List accounts failed.")
                return False

    def delete_message(self, sender, message, idx):
        """
        Request to deletes a specific message from the user's account and get response. 
        Attempt to reconnect if connection is lost during the operation.
        
        Args:
            sender (str): The sender of the message.
            message (str): The content of the message.
            idx (int): The index of the message in the list.
        
        Returns:
            str: A success or failure message.
        """
        data = {
            'action': 'delete_message',
            'username': self.username,
            'sender': sender,
            'message': message,
            'idx': idx
        }
        try:
            self.client.send(json.dumps(data).encode('utf-8'))
            raw = self.client.recv(1024).decode('utf-8')
            if not raw:
                raise ConnectionResetError("Empty response - possible server down")
            response = json.loads(raw)
            return response['status'] == 'success'          
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            print("Connection lost during delete message. Attempting to reconnect...")
            if self.reconnect():
                # Retry delete_message once after reconnect
                return self.delete_message(sender, message, idx)
            else:
                print("Failed to reconnect. Delete message failed.")
                return False

    def delete_account(self):
        """
        Request to delete the current user's account from the server and get response. 
        Attempt to reconnect if connection is lost during the operation.
        
        Returns:
            str: A success or failure message.
        """
        data = {
            'action': 'delete_account',
            'username': self.username
        }
        try:
            self.client.send(json.dumps(data).encode('utf-8'))
            raw = self.client.recv(1024).decode('utf-8')
            if not raw:
                raise ConnectionResetError("Empty response - possible server down")
            response = json.loads(raw)
            return response['status'] == 'success'
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            print("Connection lost during delete account. Attempting to reconnect...")
            if self.reconnect():
                # Retry delete_account once after reconnect
                return self.delete_account()
            else:
                print("Failed to reconnect. Delete account failed.")
                return False

class ChatApp:
    """
    A chat application that allows users to log in, send and receive messages, 
    search for other accounts, and manage their accounts, with GUI implemented by tkinter. 
    """
    def __init__(self, root, hosts):
        """
        Initializes the chat application.
        
        Args:
            root (tk.Tk): The main application window.
            hosts (list): A list of dictionaries containing the host and port of servers.
        """
        self.root = root
        self.root.geometry("600x350")
        self.client = Client(hosts)
        self.setup_login_page()

    # Rest of the ChatApp class remains the same as in the previous implementation
    def setup_login_page(self):
        """
        Sets up the login/signup page.
        """
        self.clear_window()
        self.root.title("Log in/Sign up")
        tk.Label(self.root, text="(create a new account if the username has not been signed up)").pack()
        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root) # get username entry
        self.username_entry.pack()
        tk.Button(self.root, text="Next", command=self.validate_username).pack()

    def validate_username(self):
        """
        Validates the entered username.
        
        Displays an error message if the username is empty or contains spaces.
        """
        name = self.username_entry.get().strip() 
        if not name or " " in name:
            messagebox.showerror("Error", "Please enter a valid username. It should not be empty or contain spaces.")
        else:
            self.go_to_password_page()

    def go_to_password_page(self):
        """
        Navigates to the password entry page.
        """
        self.username = self.username_entry.get()
        self.clear_window()
        self.root.title("Log in/Sign up")
        tk.Label(self.root, text="(If the username does not exist, enter the password to sign up.)").pack()
        tk.Label(self.root, text="Password:").pack()
        self.password_entry = tk.Entry(self.root, show="*") # get password entry
        self.password_entry.pack()
        tk.Button(self.root, text="Log in/Sign up", command=self.login).pack()
        tk.Button(self.root, text="Back", command=self.setup_login_page).pack()

    def hash_password(self, password):
        """
        Hashes a password using SHA-256.
        
        Args:
            password (str): The password to hash.
        
        Returns:
            str: The hashed password.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def login(self):
        """
        Logs the user in or registers a new account if the username does not exist.
        """
        password = self.hash_password(self.password_entry.get())
        success = self.client.login(self.username, password)
        if success:
            self.setup_account_page()
        else:
            messagebox.showerror("Error", 'Incorrect password.')

    def setup_account_page(self):
        """
        Sets up the account dashboard after a successful login.
        """
        self.clear_window()
        self.root.title("Account - " + self.username)
        self.unread_label = tk.Label(self.root, text="Checking messages...")
        self.unread_label.pack()
        tk.Button(self.root, text="List accounts", command=self.setup_list_accounts_page).pack()
        tk.Button(self.root, text="Send messages", command=self.setup_send_message_page).pack()
        tk.Button(self.root, text="Read messages", command=self.read_messages).pack()
        tk.Button(self.root, text="Delete account", command=self.delete_account).pack()
        tk.Button(self.root, text="Log out", command=self.setup_login_page).pack()
        self.refresh_unread_messages()

    def refresh_unread_messages(self):
        """
        Refreshes the unread messages count every second to notify logged-in users about new undelivered messages immediately. 
        """
        if hasattr(self, "unread_label") and self.unread_label.winfo_exists():
            unread_messages = self.client.get_unread() 
            self.unread_label.config(text=f"({len(unread_messages)} unread messages)")
            self.root.after(1000, self.refresh_unread_messages)

    def setup_list_accounts_page(self):
        """
        Sets up the account search page.
        """
        self.clear_window()
        self.root.title("Search accounts")
        tk.Label(self.root, text="Search for existing accounts").pack()
        self.search_entry = tk.Entry(self.root) # get query entry
        self.search_entry.pack()
        tk.Button(self.root, text="Search", command=self.list_accounts).pack()
        tk.Button(self.root, text="Back", command=self.setup_account_page).pack()

    def list_accounts(self):
        """
        Lists all accounts that match the search query. Add a scroll bar to display all accounts comfortably. 
        """
        query = self.search_entry.get()
        response = self.client.list_accounts(query)  
        self.clear_window()
        self.root.title("Accounts List")

        # add scroll bar
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)
        canvas = tk.Canvas(main_frame)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        account_frame = tk.Frame(canvas)
        canvas.create_window((0, 0), window=account_frame, anchor="n", width=self.root.winfo_width())
        canvas.configure(yscrollcommand=scrollbar.set)
        for user in response:
            user_frame = tk.Frame(account_frame)
            user_frame.pack(fill="x", expand=True)
            tk.Label(user_frame, text=user).pack(anchor="center", pady=1)
        account_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        tk.Button(self.root, text="Back", command=self.setup_account_page).pack()

    def setup_send_message_page(self):
        """
        Sets up the interface for sending messages.

        Ask user to enter the recipient and message. Provides buttons to send the message or 
        navigate back to the account page.
        """
        self.clear_window()
        self.root.title("Send messages")
        tk.Label(self.root, text="Recipient:").pack()
        self.recipient_entry = tk.Entry(self.root)
        self.recipient_entry.pack()
        tk.Label(self.root, text="Message:").pack()
        self.message_entry = tk.Entry(self.root)
        self.message_entry.pack()
        tk.Button(self.root, text="Send", command=self.send_message).pack()
        tk.Button(self.root, text="Back", command=self.setup_account_page).pack()

    def send_message(self):
        """
        Sends a message to a recipient.

        Retrieves the recipient and message from the input fields and 
        sends them accordingly. Displays a success or error message 
        based on the result.
        """
        recipient = self.recipient_entry.get()
        message = self.message_entry.get()
        status, result = self.client.send_message(recipient, message)
        if status:
            messagebox.showinfo("Success", result)
        else:
            messagebox.showerror("Error", result)
    
    def read_messages(self):
        """
        Checks for unread messages.

        If there are unread messages, navigates to the unread messages 
        page. Otherwise, directs the user to the read messages result page.
        """
        unread_messages = self.client.get_unread()
        num_unread = len(unread_messages)
        if num_unread > 0:
            self.setup_unread_messages_page()
        else:
            self.setup_read_messages_result_page()

    def setup_unread_messages_page(self):
        """
        Sets up the interface for reading unread messages.

        Ask users to enter the number of messages to read. 
        """
        self.clear_window()
        self.root.title("Read messages")
        tk.Label(self.root, text="How many messages would you like to read? (Please enter an integer)").pack()
        self.per_page_entry = tk.Entry(self.root)
        self.per_page_entry.pack()
        tk.Button(self.root, text="Read", command=self.setup_unread_messages_result_page).pack()
        tk.Button(self.root, text="Back", command=self.setup_account_page).pack()

    def setup_unread_messages_result_page(self):
        """
        Displays unread messages based on the number of messages the user wants to read. 
        """
        per_page = self.per_page_entry.get() # get number of messages the user wants to read
        if not per_page.isdigit():
            messagebox.showerror("Error", "Invalid number. Please enter again.")
            self.setup_unread_messages_page()
        per_page = int(per_page)
        messages = self.client.read_unread_messages(per_page)
        self.clear_window()
        self.root.title("Read messages")
        for message in messages:
            tk.Label(self.root, text=f"{message['from']}: {message['message']}").pack()
        tk.Button(self.root, text="Back", command=self.setup_account_page).pack()

    def setup_read_messages_result_page(self):
        """
        Displays read messages with a delete option. Add a scroll bar to display all messages comfortably. 

        Each message is a button that allows deletion upon clicking. 
        """
        self.clear_window()
        self.root.title("Read Messages")
        tk.Label(self.root, text="(Click on a message to delete.)", fg="gray").pack()
        
        # add scroll bar
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)
        canvas = tk.Canvas(main_frame)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        message_frame = tk.Frame(canvas)
        canvas.create_window((0, 0), window=message_frame, anchor="n", width=self.root.winfo_width())
        canvas.configure(yscrollcommand=scrollbar.set)
        messages = self.client.read_messages()
        idx = len(messages) - 1
        for message in messages[::-1]:
            sender = message['from']
            me = message['message']

            # each message is a button that allows deletion upon clicking
            msg_button = tk.Button(message_frame, text=f"{sender}: {me}",command=lambda s=sender, m=me, i=idx: self.confirm_delete_message(s, m, i))
            msg_button.pack(fill="x", padx=10, pady=2) 
            idx -= 1
        message_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        tk.Button(self.root, text="Back", command=self.setup_account_page).pack()

    
    def confirm_delete_message(self, sender, message, idx):
        """
        Confirms the deletion of a message.

        Opens a confirmation window asking the user to confirm deleting 
        the selected message. If confirmed, the message is deleted and the interface is updated.

        Args:
            sender (str): The sender of the message.
            message (str): The message content.
            idx (int): The index of the message in the message list.
        """
        confirm_window = tk.Toplevel(self.root)
        confirm_window.title("Delete Message")
        tk.Label(confirm_window, text="Do you want to delete this message?").pack(pady=10)
        
        # delete message upon confirming deletion
        def delete_message():
            response = self.client.delete_message(sender, message, idx)
            confirm_window.destroy()
            messagebox.showinfo(message=response)
            self.setup_read_messages_result_page()
        
        tk.Button(confirm_window, text="Yes", command=delete_message).pack(side=tk.LEFT, padx=10)
        tk.Button(confirm_window, text="No", command=confirm_window.destroy).pack(side=tk.RIGHT, padx=10)

    
    def delete_account(self):
        """
        Confirms and deletes the user account.

        Opens a confirmation window asking the user to confirm account 
        deletion. If confirmed, the account is deleted and all messages 
        sent from this account are deleted from their recipients, 
        and the user is redirected to the login page.
        """
        confirm_window = tk.Toplevel(self.root)
        confirm_window.title("Delete Account")
        tk.Label(confirm_window, text="Do you want to delete this account? This will delete all your messages.").pack(pady=10)
        
        # delete account upon confirming deletion
        def delete_a():
            response = self.client.delete_account()
            confirm_window.destroy()
            messagebox.showinfo(message=response)
            self.setup_login_page()
        
        tk.Button(confirm_window, text="Yes", command=delete_a).pack(side=tk.LEFT, padx=10)
        tk.Button(confirm_window, text="No", command=confirm_window.destroy).pack(side=tk.RIGHT, padx=10)


    def clear_window(self):
        """
        Clears all widgets from the current window.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    import configparser
    config = configparser.ConfigParser()
    config.read('config.ini')
    hosts = [
        {'host': config['server']['host1'], 'port': int(config['server']['port1'])},
        {'host': config['server']['host2'], 'port': int(config['server']['port2'])},
        {'host': config['server']['host3'], 'port': int(config['server']['port3'])}
    ]
    root = tk.Tk()
    app = ChatApp(root, hosts)
    root.mainloop()