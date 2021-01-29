#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0

import ssl
import websocket

from boofuzz import *
from websocket_connection import WSConnection

def main():
    port = 443
    host = 'wss://test.com/ws'

    ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
    ws.connect(host, http_proxy_host="localhost", http_proxy_port=8080, header=["User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0"])
    ws.send("{\"id\":}")
    result = ws.recv()
    ws.close()

    """
    This example is a very simple FTP fuzzer. It uses no process monitory
    (procmon) and assumes that the FTP server is already running.
    """
    session = Session(target=Target(connection=WSConnection(host, port)))

    """
    s_initialize("test")
    s_static("{\"id\":")
    s_string("1")
    s_static("}")
    """
    
    s_initialize("test")
    s_static("{")
    s_static("\"method\"")
    s_delim(":", fuzzable=False)
    s_string("9", fuuzable=False)
    s_delim(",", fuzzable=False)
    s_static("\"params\"")
    s_delim(":", fuzzable=False)
    s_static("{")
    s_static("\"data\"")
    
    s_static("\"channel\"")
    s_delim(":", fuzzable=False)
    s_delim("\"", fuzzable=False)
    s_string("sessions")
    s_delim("\"", fuzzable=False)
    s_static("}")
    s_delim(",", fuzzable=False)
    s_static("\"id\"")
    s_delim(":", fuzzable=False)
    s_string("2")
    s_static("}")
    s_static("\r\n")

    session.connect(s_get("test"))
    session.fuzz()


def define_proto(session):
    # disable Black formatting to keep custom indentation
    # fmt: off
    user = Request("user", children=(
        String("key", "USER"),
        Delim("space", " "),
        String("val", "anonymous"),
        Static("end", "\r\n"),
    ))

    passw = Request("pass", children=(
        String("key", "PASS"),
        Delim("space", " "),
        String("val", "james"),
        Static("end", "\r\n"),
    ))

    stor = Request("stor", children=(
        String("key", "STOR"),
        Delim("space", " "),
        String("val", "AAAA"),
        Static("end", "\r\n"),
    ))

    retr = Request("retr", children=(
        String("key", "RETR"),
        Delim("space", " "),
        String("val", "AAAA"),
        Static("end", "\r\n"),
    ))
    # fmt: on

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)


def define_proto_static(session):
    """Same protocol, using the static definition style."""
    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string("james")
    s_static("\r\n")

    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))


if __name__ == "__main__":
    main()

