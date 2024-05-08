# Distribute-File-Systems
OVERVIEW:
As part of this effort, one communication server and peer nodes is implemented. As of now, there is one communication server code and one peer node code. Only one communicaiton server instance needs to be up and running so that it can accept all incoming requests. Multiple instance of same peer node code can be running for different users or peer node code copies can be created and those different copies with same code can be used for different users.
The main role of communication server is to establish connection with peer node and receive all commands that user is executing and maintain queues of this command so that when inactive node becomes active, replicas of file can be created as well all previously executed operations by different users will be executed on that end.

REQUIREMENTS:

The required modules for running the codes are:

pycryptodome
sockets
Above dependency can be executed using commands as below:

pip install pycryptodome
pip install sockets
Once above dependency are installed, activate communication server using command:

py CommunicationServer.py
As soon as communication server is active, below message will be displayed on console:

Master node is initialized and is listening for incoming commands
Once this message is displayed, communication server is all ready and peer nodes code can be initialized. As mentioned in overview section, multiple instance of one file can be used or different replica of that peerNode.py code can be done, one for each user.
To start peer node, run the command

py peerNode.py
Once peer node is running, it will ask for username and then password for that user. Trial username and passwords are:

username: Hemanth, password: Hemanth1234
username: Nilay, password: Nilay1234
username: Shailesh, password: Shailesh1234
username: Budhini, password: Budhini1234
username: Nishitha, password: Nishitha1234
User needs to be validated before performing any operations or using the system. As soon as user is validated, system will display list of available commands as well as if some commands were executed before this node was active, those commands will also be displayed. The commands available for execution are:

CREATE -<filename> -<hemanthPermissions> -<nishithaPermissions> -<shaileshPermissions>, -<budhiniPermissions> -<nilayPermissions>

 where user permission is in <READ, WRITE, DELETE, RESTORE> order and 1 stands for allow and 0 stands for deny

WRITE -<filename> -<contentToBeWritten>

READ -<filename>

DELETE -<filename>

RESTORE -<filename>

REGENERATE -key

ConnectionDisconnect -y

User can type in any of the above commands, the <filename> will be replaced by actual filename, same with other userpermissions value.

As soon as commands are executed, all status related messages, like file creation started, file created, time of execution, exception in case any is there, will be displayed.

Note: In peerNode.py, directory path where all file operation will be executed, it is set to

For Nilay: D:/Nilay Personal/PCS_Project/Nilay
For Hemanth: D:/Nilay Personal/PCS_Project/Hemanth
For Nishitha: D:/Nilay Personal/PCS_Project/Nishitha
For Shailesh: D:/Nilay Personal/PCS_Project/Shailesh
For Budhini: D:/Nilay Personal/PCS_Project/Budhini
Above location is as per the PC used for development, before running this code, please make sure you have 5 folders, one for each user created and replace above with path on your PC.

There is one recycle bin location set to D:/Nilay Personal/PCS_Project/PCS_RECYCLE, please create one recycle folder which will be used for delete and restore file operations and update this path to path on your PC.

