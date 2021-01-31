#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0
# This file is a part of Websockets BooFuzz Fuzzer

import ssl
import websocket

from boofuzz import *
from websocket_connection import WSConnection

def main():
    """ Define Websocket url. """
    host = 'wss://test.com/ws'
    port = 443

    """ Create new WSConnection session. """
    session = Session(target=Target(connection=WSConnection(host, port)))
    define_proto_static(session)
    session.fuzz()

def define_proto_static(session):
    """Same protocol, using the static definition style."""
    s_initialize("websocket")
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

    session.connect(s_get("websocket"))

if __name__ == "__main__":
    main()

