# This file is a part of Websockets BooFuzz Fuzzer

from __future__ import absolute_import

import errno
import socket
import sys
import ssl
import websocket

from future.utils import raise_

from boofuzz import exception
from boofuzz.connections import base_socket_connection

from websocket._exceptions import WebSocketConnectionClosedException

# ignore ssl certificate so that I can use ZAP Proxy for monitoring
def open_connection(url):
    ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
    ws.connect(url, http_proxy_host="localhost", http_proxy_port=8080, header=["User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0"])
    return ws

class WSConnection(base_socket_connection.BaseSocketConnection):
    """BaseSocketConnection implementation for use with TCP Sockets.
    .. versionadded:: 0.2.0
    Args:
        host (str): Hostname or IP adress of target system.
        port (int): Port of target service.
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
        server (bool): Set to True to enable server side fuzzing.
    """

    def __init__(self, host, port, send_timeout=5.0, recv_timeout=5.0, server=False):
        super(WSConnection, self).__init__(send_timeout, recv_timeout)

        self.host = host
        self.port = port
        self.server = server

    def close(self):
        if self._sock:
            self._sock.close()
        super(WSConnection, self).close()

    def open(self):
        self._sock = open_connection(self.host)

        # call superclass to set timeout sockopt
        #super(WSConnection, self).open()


    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target.
        Args:
            max_bytes (int): Maximum number of bytes to receive.
        Returns:
            Received data.
        """
        data = b""

        try:
            data = self._sock.recv()
        except socket.timeout:
            data = b""
        except socket.error as e:
            if e.errno == errno.ECONNABORTED:
                raise_(
                    exception.BoofuzzTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror),
                    None,
                    sys.exc_info()[2],
                )
            elif (e.errno == errno.ECONNRESET) or (e.errno == errno.ENETRESET) or (e.errno == errno.ETIMEDOUT):
                raise_(exception.BoofuzzTargetConnectionReset(), None, sys.exc_info()[2])
            elif e.errno == errno.EWOULDBLOCK:  # timeout condition if using SO_RCVTIMEO or SO_SNDTIMEO
                data = b""
            else:
                raise

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!
        Args:
            data: Data to send.
        Returns:
            int: Number of bytes actually sent.
        """
        num_sent = 0

        try:
            num_sent = self._sock.send(data)
        except (WebSocketConnectionClosedException, ssl.SSLError, ConnectionResetError):
            self._sock = open_connection(self.host)
            num_sent = self._sock.send(data)

        result = self._sock.recv()
        return num_sent

    @property
    def info(self):
        return "{0}".format(self.host)
