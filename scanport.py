import nmap
import optparse
import signal
import sys
import multiprocessing
from threading import Thread
from socket import *

screenLock = multiprocessing.Semaphore(value = 1)
def connScan(ip, port):
        try:
                s = socket(AF_INET, SOCK_STREAM)
                s.connect((ip, port))
                s.send(b'ViolentPython \r\n')
                results = s.recv(100)
                screenLock.acquire()
                print('[+] {0}/tcp open'.format(port))
                if results:
                        print('\t', end = '')
                        print(str(results,
                                encoding = 'utf-8').replace('\n', '\n\t'))
        except KeyboardInterrupt:
                screenLock.acquire()
                print('Ctrl-c')
                sys.exit()
        except:
                screenLock.acquire()
                print('[-] {0}/tcp closed'.format(port))
        finally:
                screenLock.release()
                s.close()

def portScan(ip, ports):
        try:
                ip = gethostbyname(ip)
        except:
                print('[-] Cannot resolv "{0}" Unknown host'.format(ip))
                return
        try:
                tname = gethostbyaddr(ip)
                print('[+] Scan Results for: ', tname[0])
        except:
                print('[+] Scan Results for: ',  ip)
        setdefaulttimeout(1)
        for tp in ports:
                t = Thread(target = connScan, args = (ip, int(tp)))
                t.start()
                # print('Scanning port ' + tp)
                # connScan(ip, int(tp))

def nmapScan(ip, port):
        nmScan = nmap.PortScanner()
        nmScan.scan(ip, port)
        state = nmScan[ip]['tcp'][int(port)]['state']
        print("[*] {0} tcp/{1} state {2}".format(ip, port, state))

def main():
        parser = optparse.OptionParser("Usage %prog -H <target host> -P " +
                        "<target port>")
        parser.add_option('-H', dest = 'ip', type = 'string',
                        help = 'specify target host')
        parser.add_option('-P', dest = 'port', type = 'string',
                        help = 'specify target port(s) separated by comma')
        opts, args = parser.parse_args()
        ip = opts.ip
        ports = str(opts.port).split(',')
        if ip is None or ports is None:
                print('[-] You must specify a target host and port(s).')
                parser.print_help()
                sys.exit()
        # portScan(ip, ports)
        for p in ports:
                nmapScan(ip, p)

if __name__ == '__main__':
        main()
