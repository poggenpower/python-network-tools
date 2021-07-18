import socket	#for sockets
import sys	#for exit
import time
import argparse

def main(args):
    host = args.remote_host
    port = args.remote_port
    msg_in = args.message


    addr_family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    # create dgram udp socket
    try:
        s = socket.socket(addr_family, socket.SOCK_DGRAM)
    except socket.error:
        print('Failed to create socket')
        sys.exit()

    try :
        #Set the whole string
        for x in range(10):
            msg = f"{msg_in}:{x}".encode()
            s.sendto(msg, (host, port))
            
            # receive data from client (data, addr)
            d = s.recvfrom(1024)
            reply = d[0]
            addr = d[1]
        
            print(f"Server {addr} reply :  {reply}")
            time.sleep(0.500)

        time.sleep(35)
        for x in range(10):
            msg = f"{msg_in}:{x}".encode()
            s.sendto(msg, (host, port))
            
            # receive data from client (data, addr)
            d = s.recvfrom(1024)
            reply = d[0]
            addr = d[1]
        
            print(f"Server {addr} reply :  {reply}")



    except socket.error as msg:
        print('Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-H", "--remote-host", default="localhost")
    parser.add_argument("-r", "--remote-port", type=int,  default=51820)
    parser.add_argument("-m", "--message", default="Hello World")
    parser.add_argument("-6", "--ipv6", action="store_true", default=False)

    args = parser.parse_args()

    main(args)