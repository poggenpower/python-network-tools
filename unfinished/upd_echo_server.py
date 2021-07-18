import os
import socket
import threading
import socketserver
import logging
from typing import Callable

file_path = os.path.splitext(os.path.realpath(__file__))[0]

logging.basicConfig(level=logging.DEBUG)

logFormatter = logging.Formatter("%(asctime)s [%(filename)s:%(lineno)s - %(funcName)20s() ] [%(levelname)-5.5s]  %(message)s")

fileHandler = logging.FileHandler("{0}.log".format(file_path))
fileHandler.setFormatter(logFormatter)
logging.getLogger().addHandler(fileHandler)

# consoleHandler = logging.StreamHandler()
logging.getLogger().handlers[0].setFormatter(logFormatter) # reconfigure the root logger
# logging.getLogger().addHandler(consoleHandler)

class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        cur_thread = threading.current_thread()
        my_data = threading.local()
        try:
            x = my_data.x
        except AttributeError:
            x = 0
        logging.debug(f"{cur_thread.name} {self.client_address} count {x} wrote:")
        logging.debug(data)
        my_data.x = x + 1
        socket.sendto(data.upper(), self.client_address)

class UDPv6Server(socketserver.UDPServer):
    address_family = socket.AF_INET6

    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: Callable[..., socketserver.BaseRequestHandler], bind_and_activate=True) -> None:
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=False)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        if bind_and_activate:
            try:
                self.server_bind()
                self.server_activate()
            except:
                self.server_close()
                raise

class ThreadedUDPServer(socketserver.ThreadingMixIn, UDPv6Server):
    pass

def client(ip, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.sendall(bytes(message, 'ascii'))
        response = str(sock.recv(1024), 'ascii')
        print("Received: {}".format(response))

if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = "", 51821

    server = ThreadedUDPServer((HOST, PORT), ThreadedUDPRequestHandler)
    server.address_family = socket.AF_INET6
    with server:
        ip, port, _, _ = server.server_address

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        print("Server loop running in thread:", server_thread.name)

        input("Press Enter to continue...")
