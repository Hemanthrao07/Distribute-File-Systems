import socket
import threading
import time
from Crypto.Cipher import AES  # Advanced Encryption Standard
from Crypto.Util.Padding import pad, unpad

# Assigning port
PORT = 5051

# Dynamically getting the local machine IPv4 address
NODE = socket.gethostbyname(socket.gethostname())

# Creating a socket
node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Defining the address tuple which is needed to bind the socket to a specific port
ADDRESS = (NODE, PORT)

# Binding the socket
node_socket.bind(ADDRESS)

sizeOfMessage = 64  # This contains the size of the actual message
FORMAT = 'utf-8'
nodeDisconnectionInfo = "ConnectionDisconnect"
acknowledgementInfo = "Message is received successfully"

# This data structure holds the connection details of the all the nodes in the network
nodes_connected = []

nodeAddresses = {
    "Hemanth": "",
    "Nishitha": "",
    "shailesh": "",
    "Budhini": "",
    "Nilay": ""
}

hemanthCommandsQueue = []
nishithaCommandsQueue = []
shaileshCommandsQueue = []
budhiniCommandsQueue = []
nilayCommandsQueue = []

secretKey = b'~$?R\x0e\x14\xab\xbd\xc3\xdeL\xa1N(\x83\xd5T\xdb1\x83\xd9ANy\xc4\xe5\x19\xb6s\x82\xc1\x8e'


def messageEncryption(plainText):
    # Function converts plain text to bytes format and uses AES with cipher block chaining mode and returns random number and cipher text
    plain_text_bytes = plainText.encode()
    encryption = AES.new(secretKey, AES.MODE_CBC)
    encrypted_text = encryption.encrypt(pad(plain_text_bytes, AES.block_size))
    return encryption.iv, encrypted_text


def messageDecryption(nonce, cipherText):
    # Function attempts to decrypt provided cipher text and return plain text
    decryption = AES.new(secretKey, AES.MODE_CBC, iv=nonce)
    decrypted_text = unpad(decryption.decrypt(cipherText), AES.block_size)
    return str(decrypted_text)

# this function broadcast input commands to active nodes and if nodes are inactive, update the queue
# and send when they are active
def broadcastCommandsToActiveNodes(message, current_connection):
    # update queues for all nodes
    for connectedNode in nodeAddresses:
        if nodeAddresses[connectedNode] != "":
            pass
        else:
            if connectedNode == "Hemanth":
                hemanthCommandsQueue.append(message)
            if connectedNode == "Nishitha":
                nishithaCommandsQueue.append(message)
            if connectedNode == "Shailesh":
                shaileshCommandsQueue.append(message)
            if connectedNode == "Budhini":
                budhiniCommandsQueue.append(message)
            if connectedNode == "Nilay":
                nilayCommandsQueue.append(message)
    # send input message to connected nodes out of all
    for connection in nodes_connected:
        if connection == current_connection:
            pass
        else:
            message_iv, message_enc = messageEncryption(message)
            connection.send(message_iv)
            time.sleep(1)
            connection.send(message_enc)


# This function gets the node request, perform the action and then broadcast it to other node
def handleMultipleNodes(conn, addr):
    print(f"Node with address {addr} is connected")

    isNodeConnected = True
    while isNodeConnected:
        try:
            node_message_iv = conn.recv(16)
            node_message_enc = conn.recv(2048)
            node_message = messageDecryption(node_message_iv, node_message_enc)
            node_message_len = len(node_message)
            node_message = node_message[2:node_message_len - 1]
            # If the node wants to disconnect, this message allows it to disconnect by exiting the while
            # loop and executing the close connection command
            if node_message.split(" ")[0] == nodeDisconnectionInfo:
                print(f"Node with address {addr} is disconnected")
                disconnect_iv, disconnect_msg = messageEncryption("Connection disconnected!")
                conn.send(disconnect_iv)
                time.sleep(1)
                conn.send(disconnect_msg)
                isNodeConnected = False
                nodes_connected.remove(conn)

            else:
                print(f"Received command - {node_message} from node - {addr}")
                broadcastCommandsToActiveNodes(node_message, conn)
        except:
            pass

    conn.close()


# This functions opens the listening socket and initializes the nodes concurently
def socketInitialization():
    node_socket.listen()
    while True:
        conn, addr = node_socket.accept()
        user_iv = conn.recv(2048)
        user_enc = conn.recv(2048)
        user = messageDecryption(user_iv, user_enc)
        user = user[2:len(user) - 1]

        # Storing the nodes address in the data list
        if conn in nodes_connected:
            clear_iv, clear_enc = messageEncryption("CLEAR")
            conn.send(clear_iv)
            time.sleep(1)
            conn.send(clear_enc)
        else:
            nodes_connected.append(conn)
            nodeAddresses[user] = conn
            if user == "Hemanth" and len(hemanthCommandsQueue) != 0:
                for command in hemanthCommandsQueue:
                    message_iv, message_enc = messageEncryption(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
                clear_iv, clear_enc = messageEncryption("CLEAR")
                conn.send(clear_iv)
                time.sleep(1)
                conn.send(clear_enc)
            if user == "Nishitha" and len(nishithaCommandsQueue) != 0:
                for command in nishithaCommandsQueue:
                    message_iv, message_enc = messageEncryption(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
                clear_iv, clear_enc = messageEncryption("CLEAR")
                conn.send(clear_iv)
                time.sleep(1)
                conn.send(clear_enc)
            if user == "Shailesh" and len(shaileshCommandsQueue) != 0:
                for command in shaileshCommandsQueue:
                    message_iv, message_enc = messageEncryption(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
                clear_iv, clear_enc = messageEncryption("CLEAR")
                conn.send(clear_iv)
                time.sleep(1)
                conn.send(clear_enc)
            if user == "Budhini" and len(budhiniCommandsQueue) != 0:
                for command in budhiniCommandsQueue:
                    message_iv, message_enc = messageEncryption(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
                clear_iv, clear_enc = messageEncryption("CLEAR")
                conn.send(clear_iv)
                time.sleep(1)
                conn.send(clear_enc)
            if user == "Nilay" and len(nilayCommandsQueue) != 0:
                for command in budhiniCommandsQueue:
                    message_iv, message_enc = messageEncryption(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
            clear_iv, clear_enc = messageEncryption("CLEAR")
            conn.send(clear_iv)
            time.sleep(1)
            conn.send(clear_enc)

            # Threading to handle multiple nodes
        thread = threading.Thread(target=handleMultipleNodes, args=(conn, addr))
        thread.start()


if __name__ == "__main__":
    print("Master node is initialized and is listening for incoming commands")
    socketInitialization()
