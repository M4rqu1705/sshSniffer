#!/usr/bin/env python

#Dictionary to store IP addresses and the amount of login attempts they made
loginAttempts = {}

#Variable to exclude garbage messages
nameLengthLimit = 50

#Open login log file in readonly mode
with open('/var/log/auth.log', 'r') as authlog:
    #Check each line in file
    for line in authlog:
        #Search for the string  "authentication failure" in each line
        if "authentication failure" in line:
            #Split line in order to store the source IP address
            username = line.split('rhost=') [-1].split('user')[0]

            #Store IP address
            if loginAttempts.has_key(username):
                loginAttempts[username] +=1
            else:
                loginAttempts[username] = 1

#Print values of loginAttempts dictionary
for key, value in loginAttempts.iteritems():
    if len(str(key)) < nameLengthLimit:
        print str(key).rstrip() + ' -> ' + str(value)

