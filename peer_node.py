import os
import shutil
import socket
import sys
import threading
import time
import secrets
from Crypto.Cipher import AES  # Advanced Encryption Standard
from Crypto.Util.Padding import pad, unpad

fileLock = threading.Lock()

# Assigning port
PORT = 5051
sizeOfMessage = 64  # This containes the size of the actual message
messageFormat = 'utf-8'
nodeDisconnectMessage = "ConnectionDisconnect"

# Dynamically getting the local machine IPv4 address
# NODE = socket.gethostbyname(socket.gethostname())
NODE = socket.gethostbyname(socket.gethostname())

# Defining the address tuple which is needed to connect the socket to a specific port
ADDRESS = (NODE, PORT)
print(ADDRESS)

# Creating a socket
node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

secretKey = b'~$?R\x0e\x14\xab\xbd\xc3\xdeL\xa1N(\x83\xd5T\xdb1\x83\xd9ANy\xc4\xe5\x19\xb6s\x82\xc1\x8e'
listOfFiles = []

recycleBinLocation = "D:/Nilay Personal/PCS_Project/PCS_RECYCLE"
recycleBinLocation = recycleBinLocation.replace('/', '\\')

hemanthReadFilePermissions = []
nishithaReadFilePermissions = []
shaileshReadFilePermissions = []
budhiniReadFilePermissions = []
nilayReadFilePermissions = []

hemanthWriteFilePermissions = []
nishithaWriteFilePermissions = []
shaileshWriteFilePermissions = []
budhiniWriteFilePermissions = []
nilayWriteFilePermissions = []

hemanthDeleteFilePermissions = []
nishithaDeleteFilePermissions = []
shaileshDeleteFilePermissions = []
budhiniDeleteFilePermissions = []
nilayDeleteFilePermissions = []

hemanthRestoreFilePermissions = []
nishithaRestoreFilePermissions = []
shaileshRestoreFilePermissions = []
budhiniRestoreFilePermissions = []
nilayRestoreFilePermissions = []


def messageEncryption(plainText, secretKey):
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


# This function sends data to the NODE
def sendRequestsToNode(user):
    while True:
        continueWithRequest = True
        try:
            msg = input("Please provide the command: ")
            forward = msg
            commands = msg.split(' -')
            msg = commands[0]
            file_name = commands[1]
            startTime = time.time()
            if msg == "ConnectionDisconnect":
                msg_iv, msg_enc = messageEncryption(forward, secretKey)
                node_socket.send(msg_iv)
                node_socket.send(msg_enc)
                print("You are disconnected from file system. Please close the terminal!")
                break
            content = None
            permissions = {
                "Hemanth": [],
                "Nishitha": [],
                "Shailesh": [],
                "Budhini": [],
                "Nilay": []
            }
            if msg == "WRITE":
                try:
                    content = commands[2]
                    content_iv, content = messageEncryption(content, secretKey)
                except:
                    pass
            if msg == "CREATE":
                try:
                    permissions["Hemanth"] = commands[2].split(',')
                    permissions["Nishitha"] = commands[3].split(',')
                    permissions["Shailesh"] = commands[4].split(',')
                    permissions["Budhini"] = commands[5].split(',')
                    permissions["Nilay"] = commands[6].split(',')
                except:
                    pass

            if msg == "CREATE":
                createFile(file_name, file_path, permissions["Hemanth"],
                           permissions["Nishitha"],
                           permissions["Shailesh"],
                           permissions["Budhini"],
                           permissions["Nilay"])

            elif msg == "WRITE":
                if file_name in globals()[f"{user.lower()}WriteFilePermissions"]:
                    writeToFile(file_name, file_path, content, content_iv)
                else:
                    print("This user is not having sufficient permissions to execute WRITE Operation")
                    continueWithRequest = False

            elif msg == "READ":
                if file_name in globals()[f"{user.lower()}ReadFilePermissions"]:
                    readFile(file_name, file_path)
                else:
                    print("This user is not having sufficient permissions to execute READ Operation")
                    continueWithRequest = False

            elif msg == "DELETE":
                if file_name in globals()[f"{user.lower()}DeleteFilePermissions"]:
                    deleteFile(file_name, file_path)
                else:
                    print("This user is not having sufficient permissions to execute DELETE Operation")
                    continueWithRequest = False

            elif msg == "RESTORE":
                if file_name in globals()[f"{user.lower()}RestoreFilePermissions"]:
                    restoreFile(file_name, file_path)
                else:
                    print("This user is not having sufficient permissions to execute RESTORE Operation")
                    continueWithRequest = False
            elif msg == "REGENERATE":
                newKeyGeneration(listOfFiles, file_path)

            endTime = time.time()
            executionTime = endTime - startTime
            print(f"Execution of user command took {executionTime} seconds")
            if continueWithRequest:
                msg_iv, msg_enc = messageEncryption(forward, secretKey)
                node_socket.send(msg_iv)
                node_socket.send(msg_enc)
        except:
            print("Something went wrong in sendRequestsToNode function execution")


def getRequestFromNodes():
    while True:
        try:
            message_iv = node_socket.recv(16)
            message_enc = node_socket.recv(16384)
            message = messageDecryption(message_iv, message_enc)
            message_length = len(message)
            msg = message[2:message_length - 1]

            commands = msg.split(' -')
            msg = commands[0]
            file_name = commands[1]
            if msg == "WRITE":
                try:
                    content = commands[2]
                    content_iv, content = messageEncryption(content, secretKey)
                except:
                    pass
            if msg == "CREATE":
                try:
                    permissionsForHemanth = commands[2]
                    permissionsForNishitha = commands[3]
                    permissionsForShailesh = commands[4]
                    permissionsForBudhini = commands[5]
                    permissionsForNilay = commands[6]
                except:
                    pass

            if msg == "CREATE":
                createFile(file_name, file_path, permissionsForHemanth, permissionsForNishitha, permissionsForShailesh,
                           permissionsForBudhini, permissionsForNilay)
            elif msg == "WRITE":
                writeToFile(file_name, file_path, content, content_iv)
            elif msg == "READ":
                readFile(file_name, file_path)
            elif msg == "DELETE":
                deleteFile(file_name, file_path)
            elif msg == "RESTORE":
                restoreFile(file_name, file_path)
            elif msg == "REGENERATE":
                newKeyGeneration(listOfFiles, file_path)
        except:
            print("Something went wrong in getRequestFromNodes function execution")


def getRequestFromQueue(queue):
    try:
        message = queue
        message_length = len(message)
        if message[0] == "b":
            msg = message[2:message_length - 1]
        else:
            msg = message
        print(msg)
        commands = msg.split(' -')
        msg = commands[0]
        file_name = commands[1]
        if msg == "WRITE":
            try:
                content = commands[2]
                content_iv, content = messageEncryption(content, secretKey)
            except:
                pass
        if msg == "CREATE":
            try:
                permissionsForHemanth = commands[2]
                permissionsForNishitha = commands[3]
                permissionsForShailesh = commands[4]
                permissionsForBudhini = commands[5]
                permissionsForNilay = commands[6]
            except:
                pass

        if msg == "CREATE":
            createFile(file_name, file_path, permissionsForHemanth, permissionsForNishitha, permissionsForShailesh,
                       permissionsForBudhini, permissionsForNilay)
        elif msg == "WRITE":
            writeToFile(file_name, file_path, content, content_iv)
        elif msg == "READ":
            readFile(file_name, file_path)
        elif msg == "DELETE":
            deleteFile(file_name, file_path)
        elif msg == "RESTORE":
            restoreFile(file_name, file_path)
        elif msg == "REGENERATE":
            newKeyGeneration(listOfFiles, file_path)
    except:
        print("Something went wrong in getRequestsFromQueue function execution")


def createFile(nameOfFileToBeCreated, pathOfDirectory, hemanthPermissions,
               nishithaPermissions,
               shaileshPermissions,
               budhiniPermissions,
               nilayPermissions):
    print("Trying to create file now!")
    global listOfFiles


    if hemanthPermissions[0] == "1":
        hemanthReadFilePermissions.append(nameOfFileToBeCreated)
    if hemanthPermissions[1] == "1":
        hemanthWriteFilePermissions.append(nameOfFileToBeCreated)
    if hemanthPermissions[2] == "1":
        hemanthDeleteFilePermissions.append(nameOfFileToBeCreated)
    if hemanthPermissions[3] == "1":
        hemanthRestoreFilePermissions.append(nameOfFileToBeCreated)

    if nishithaPermissions[0] == "1":
        nishithaReadFilePermissions.append(nameOfFileToBeCreated)
    if nishithaPermissions[1] == "1":
        nishithaWriteFilePermissions.append(nameOfFileToBeCreated)
    if nishithaPermissions[2] == "1":
        nishithaDeleteFilePermissions.append(nameOfFileToBeCreated)
    if nishithaPermissions[3] == "1":
        nishithaRestoreFilePermissions.append(nameOfFileToBeCreated)

    if shaileshPermissions[0] == "1":
        shaileshReadFilePermissions.append(nameOfFileToBeCreated)
    if shaileshPermissions[1] == "1":
        shaileshWriteFilePermissions.append(nameOfFileToBeCreated)
    if shaileshPermissions[2] == "1":
        shaileshDeleteFilePermissions.append(nameOfFileToBeCreated)
    if shaileshPermissions[3] == "1":
        shaileshRestoreFilePermissions.append(nameOfFileToBeCreated)

    if budhiniPermissions[0] == "1":
        budhiniReadFilePermissions.append(nameOfFileToBeCreated)
    if budhiniPermissions[1] == "1":
        budhiniWriteFilePermissions.append(nameOfFileToBeCreated)
    if budhiniPermissions[2] == "1":
        budhiniDeleteFilePermissions.append(nameOfFileToBeCreated)
    if budhiniPermissions[3] == "1":
        budhiniRestoreFilePermissions.append(nameOfFileToBeCreated)

    if nilayPermissions[0] == "1":
        nilayReadFilePermissions.append(nameOfFileToBeCreated)
    if nilayPermissions[1] == "1":
        nilayWriteFilePermissions.append(nameOfFileToBeCreated)
    if nilayPermissions[2] == "1":
        nilayDeleteFilePermissions.append(nameOfFileToBeCreated)
    if nilayPermissions[3] == "1":
        nilayRestoreFilePermissions.append(nameOfFileToBeCreated)

    f_path = pathOfDirectory + '\\' + nameOfFileToBeCreated
    if os.path.exists(f_path):
        print("File already exists")
    else:
        fp = open(f_path, 'x')
        fp.close()
        print("File is successfully created!")
        listOfFiles.append(nameOfFileToBeCreated)


def writeToFile(nameOfFileToBeUpdated, pathOfDirectory, file_content, content_iv):
    print("Trying to write content to file")
    pathOfFile = pathOfDirectory + '\\' + nameOfFileToBeUpdated

    # locking the resource so that other users can see updated content only
    fileLock.acquire()
    with open(pathOfFile, 'wb') as file:
        file.write(content_iv)
        file.write(file_content)
        file.close()
    fileLock.release()
    print("Content of file updated!")


def readFile(fileToBeDeleted, pathOfDirectory):
    print("Trying to read content from file")
    pathOfFile = pathOfDirectory + '\\' + fileToBeDeleted
    with open(pathOfFile, 'rb') as file:
        content_nonce = file.read(16)
        content = file.read()
        file.close()
        content = messageDecryption(content_nonce, content)
        print(content)
        return content


def deleteFile(fileToBeDeleted, pathOfDirectory):
    global listOfFiles
    print("Trying to delete file")
    pathOfFile = pathOfDirectory + '\\' + fileToBeDeleted

    sourceLocation = pathOfFile
    destinationLocation = recycleBinLocation
    try:
        shutil.move(sourceLocation, destinationLocation)
        print("File deleted successfully!")
    except:
        os.remove(pathOfFile)
    listOfFiles.remove(fileToBeDeleted)


def restoreFile(fileToBeRestored, directoryLocation):
    global listOfFiles
    print("Trying to restore deleted file")
    pathOfFile = directoryLocation

    DestinationLocation = pathOfFile
    sourceLocation = recycleBinLocation + '\\' + fileToBeRestored
    try:
        shutil.copy(sourceLocation, DestinationLocation)
        print(f"File Restored Successfully at {DestinationLocation}")
    except:
        pass
    listOfFiles.append(fileToBeRestored)


def newKeyGeneration(listOfFiles, file_path):
    global secretKey
    print(listOfFiles)
    newKey = secrets.token_bytes(16)
    for ele in listOfFiles:
        message = readFile(ele, file_path)
        content_iv, content = messageEncryption(message, newKey)
        writeToFile(ele, file_path, content, content_iv)
    print("New key is created successfully")
    secretKey = newKey

if __name__ == "__main__":

    user = input("Username: ")
    if user == "Hemanth":
        password = input("Enter your password: ")
        while password != "Hemanth1234":
            print("Entered password is not valid, please try again!")
            password = input("Enter your password: ")
        file_path = "D:/Nilay Personal/PCS_Project/Hemanth"
        file_path = file_path.replace('/', '\\')

    elif user == "Nishitha":
        password = input("Enter your password: ")
        while password != "Nishitha1234":
            print("Entered password is not valid, please try again!")
            password = input("Enter your password: ")
        file_path = "D:/Nilay Personal/PCS_Project/Nishitha"
        file_path = file_path.replace('/', '\\')
    elif user == "Budhini":
        password = input("Enter your password: ")
        while password != "Budhini1234":
            print("Entered password is not valid, please try again!")
            password = input("Enter your password: ")
        file_path = "D:/Nilay Personal/PCS_Project/Budhini"
        file_path = file_path.replace('/', '\\')

    elif user == "Shailesh":
        password = input("Enter your password: ")
        while password != "Shailesh1234":
            print("Entered password is not valid, please try again!")
            password = input("Enter your password: ")
        file_path = "D:/Nilay Personal/PCS_Project/Shailesh"
        file_path = file_path.replace('/', '\\')

    elif user == "Nilay":
        password = input("Enter your password: ")
        while password != "Nilay1234":
            print("Entered password is not valid, please try again!")
            password = input("Enter your password: ")
        file_path = "D:/Nilay Personal/PCS_Project/Nilay"
        file_path = file_path.replace('/', '\\')

    # file_path = "D:/Nilay Personal/PCS_Project"
    # file_path = file_path.replace('/', '\\')
    print(f"Welcome {user}")
    print("Available commands are as below:")
    print("1. CREATE -<filename> -<hemanthPermissions> -<nishithaPermissions> -<shaileshPermissions>, -<budhiniPermissions> -<nilayPermissions>")
    print("where user permission is in <READ, WRITE, DELETE, RESTORE> order")
    print("2. WRITE -<filename> -<contentToBeWritten>")
    print("3. READ -<filename>")
    print("4. DELETE -<filename>")
    print("5. RESTORE -<filename>")
    print("6. REGENERATE -key")
    print("7. ConnectionDisconnect -y")
    # Connecting the socket
    node_socket.connect(ADDRESS)

    user_iv, user_enc = messageEncryption(user, secretKey)
    node_socket.send(user_iv)
    time.sleep(1)
    node_socket.send(user_enc)

    queue_iv = node_socket.recv(16)
    queue_enc = node_socket.recv(2048)
    queue = messageDecryption(queue_iv, queue_enc)
    queue = queue[2:len(queue) - 1]

    if queue == "CLEAR" or queue == "b'CLEAR'":
        pass
    else:
        while queue != "CLEAR" and queue != "b'CLEAR'":
            getRequestFromQueue(queue)
            queue_iv = node_socket.recv(16)
            queue_enc = node_socket.recv(2048)
            queue = messageDecryption(queue_iv, queue_enc)
            queue = queue[2:len(queue) - 1]

    send_thread = threading.Thread(target=sendRequestsToNode, args=(user,))
    send_thread.start()

    recv_thread = threading.Thread(target=getRequestFromNodes, args=())