#!/usr/bin/env python
# Super simple script that listens to a local UDP port and relays all packets to an arbitrary remote host.
# Packets that the host sends back will also be relayed to the local UDP client.
# Works with Python 2 and 3

import sys
import socket
import os
import logging
import argparse
import threading
import queue
from typing import Tuple
from datetime import datetime


__author__ = "Thomas Laubrock"
__version__ = "0.1.0"
__license__ = "GPL 3"

SOCKETTIMEOUT = 20

file_path = os.path.splitext(os.path.realpath(__file__))[0]

logging.basicConfig(level=logging.INFO)

logFormatter = logging.Formatter(
    "%(asctime)s [%(filename)s:%(lineno)s - %(funcName)20s() ] [%(levelname)-5.5s]  %(message)s")

fileHandler = logging.FileHandler("{0}.log".format(file_path))
fileHandler.setFormatter(logFormatter)
logging.getLogger().addHandler(fileHandler)

# consoleHandler = logging.StreamHandler()
logging.getLogger().handlers[0].setFormatter(
    logFormatter)  # reconfigure the root logger
# logging.getLogger().addHandler(consoleHandler)


# Whether or not to print the IP address and port of each packet received
debug = False

class RelayClient:

    def __init__(self, queue: Tuple, thread, stop_vent, last_comm) -> None:
        self.queue = queue
        self.thread = thread
        self.stop_event = stop_vent
        self.last_comm = last_comm

def fail(reason):
	logging.error(reason)
	sys.exit(1)


def get_address_family(hostname, port=53):
    """
    returns socket.AF_INET6 if dns record exist and IPv6 is supported
     else  socket.AF_INET
    """
    if socket.has_ipv6:
        addr_family = [answer[0] for answer in socket.getaddrinfo(hostname, port)]
        if socket.AF_INET6 in addr_family:
            return socket.AF_INET6
    return socket.AF_INET

def forwarding_thread(remote_host, remote_port, client, queue_in: queue.Queue, queue_out: queue.Queue, stop_event: threading.Event):
    #TODO: Terminate if socket not used for a while
    forward_host = socket.getaddrinfo(remote_host, remote_port)[0][-1]
    forward_socket = socket.socket(get_address_family(remote_host), socket.SOCK_DGRAM)
    forward_socket.settimeout(SOCKETTIMEOUT)

    t = threading.Thread(
            target=socket_send, 
            name=f"relay for {client}", 
            args=(forward_socket, queue_in),
            kwargs={"destination_overwrite": forward_host, "stop_event": stop_event}
        )
    t.daemon = True
    t.start()

    while not stop_event.is_set():
        try:
            timeout = False
            data, addr = forward_socket.recvfrom(32768)
        except socket.timeout as to:
            timeout = True
            logging.debug(f"Have not received remote server traffic for {client} for {SOCKETTIMEOUT}s.")
        if not timeout:
            try:
                queue_out.put_nowait((data, client))
            except queue.Full:
                logging.error(f"Can put data {data} from {forward_socket}/{addr} to {queue_out}/{client}. Full")

def socket_receive(socket_in: socket.socket, queue_out: queue.Queue):
    data, addr = socket_in.recvfrom(32768)
    try:
        queue_out.put_nowait((data, addr))
    except queue.Full:
        logging.error(f"Can put data {data} from {socket_in}/{addr} to {queue_out}. Full")

def socket_send(socket_out: socket.socket, queue_in: queue.Queue, destination_overwrite=None, stop_event=threading.Event()):
    while not stop_event.is_set():
        try:
            data, addr = queue_in.get(block=True, timeout=SOCKETTIMEOUT)
        except queue.Empty:
            continue
        if destination_overwrite:
            addr = destination_overwrite
        socket_out.sendto(data, addr)


def main():

    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-l", "--local-port", type=int,  default=51820)
    parser.add_argument("-H", "--remote-host", default="localhost")
    parser.add_argument("-r", "--remote-port", type=int,  default=51821)

    args = parser.parse_args()

    local_port = args.local_port
    remote_host = args.remote_host
    remote_port = args.remote_port
    remote_server = (remote_host, remote_port)

    try:
        local_port = int(local_port)
    except:
        fail('Invalid port number: ' + str(local_port))
    try:
        remote_port = int(remote_port)
    except:
        fail('Invalid port number: ' + str(remote_port))

    try:
        if socket.has_ipv6:
            listen_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            listen_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        else:
            listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_socket.settimeout(SOCKETTIMEOUT)
        listen_socket.bind(('', local_port))
        relay_response = queue.Queue()
        listen_socket_receiver = threading.Thread(target=socket_send, name="send back to client", args=(listen_socket, relay_response))
        listen_socket_receiver.daemon = True
        listen_socket_receiver.start()
    except Exception as e:
        logging.exception("")
        fail(f"Failed to bind Server on port {str(local_port)}: {e}")

    logging.info(f"All set, listening on {str(local_port)}")

    known_clients = {}

    start_time = datetime.now()
    while True:
        try:
            timeout = False
            data, addr = listen_socket.recvfrom(32768)
        except socket.timeout as to:
            timeout = True
            logging.debug(f"Have not received client side traffic for {SOCKETTIMEOUT}s.")
        if not timeout:        
            if not known_clients.get(addr):
                logging.debug(f"New Client connection: {addr}")
                relay_forward = queue.Queue()
                stop_event = threading.Event()
                forward_thread = threading.Thread(
                        target=forwarding_thread, 
                        name=f"socket for {addr}", 
                        args=(remote_host, remote_port, addr, relay_forward, relay_response, stop_event)
                    )
                forward_thread.daemon = True
                forward_thread.start()
                known_client = RelayClient(relay_forward, forward_thread, stop_event, datetime.now())
                known_clients[addr] = known_client

            logging.debug(f"Packet received from {str(addr)}")
            # forward_socket.sendto(data, forward_server)
            known_clients[addr].queue.put_nowait((data, addr))
            known_clients[addr].last_comm = datetime.now()
        
        if (datetime.now() - start_time).seconds > SOCKETTIMEOUT:
            # run cleanup
            start_time = datetime.now()
            aged_clients = []
            for addr, client in known_clients.items():
                if (datetime.now() - client.last_comm).seconds > 4 * SOCKETTIMEOUT:
                    client.stop_event.set()
                    aged_clients.append(addr)
                    logging.info(f"No communication for {addr}. Aging out.")
            for addr in aged_clients:
                del(known_clients[addr])


if __name__ == '__main__':
    main()