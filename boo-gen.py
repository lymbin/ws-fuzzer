#!/usr/bin/python3
# This file is a part of Websockets BooFuzz Fuzzer
# From Websocket's JSON message BooFuzz Fuzzer File Generator

import argparse
import json

parser = argparse.ArgumentParser(add_help=True)
parser.add_argument("request", type=str, help="request template to fuzz")
parser.add_argument("-f", "--filename", default="ws.py", type=str, nargs="?", help="select name of fuzzing script (default is ws.py)", metavar='filename')
parser.add_argument("-s", "--host", default="wss://test.com/ws", type=str, nargs="?", help="host to fuzz", metavar='host')
parser.add_argument("-p", "--proxy", help="for proxy requests via ZAP or Burp",
                    action="store_true")

args = parser.parse_args()
request = args.request
filename = args.filename
host = args.host

with open(request) as json_file:
    contents = json.load(json_file)

def gen():
    write_init()
    gen_from_dict(contents)
    write_close()

def gen_from_dict(dictionary):
    i = False
    for x in dictionary:
        fuzz = open(filename, "a")
        if (i is True):
            fuzz.write('''    s_static(",")\n''') 
        fuzz.write('''    s_static("\\"''' + x + '''\\"")
    s_delim(":", fuzzable=False)\n''')
        fuzz.close()
        if type(dictionary[x]) is dict:
            fuzzd = open(filename, "a")
            fuzzd.write('''    s_static("{")\n''')
            fuzzd.close()
            print("%s: dictionary" % (x))
            gen_from_dict(dictionary[x])
            fuzzd = open(filename, "a")
            fuzzd.write('''    s_static("}")\n''')
            fuzzd.close()
        elif type(dictionary[x]) is str:
            fuzzs = open(filename, "a")
            fuzzs.write('''    s_delim("\\"", fuzzable=False)
    s_string("''' + dictionary[x] + '''")
    s_delim("\\"", fuzzable=False)\n''')
            fuzzs.close()
            print("%s: %s" % (x, dictionary[x]))
        elif type(dictionary[x]) is int:
            fuzzi = open(filename, "a")
            fuzzi.write('''    s_string("''' + str(dictionary[x]) + '''", fuzzable=False)\n''')
            fuzzi.close()
            print("%s: %d" % (x, dictionary[x]))
        i = True

def write_init():
    fuzz = open(filename, "w")
    fuzz.write('''#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0
# This file is a part of Websockets BooFuzz Fuzzer

import ssl
import websocket

from boofuzz import *
from websocket_connection import WSConnection

def main():
    """ Define Websocket url. """
    host = "''' + host + '''"
    port = 443

    """ Create new WSConnection session. """
    session = Session(target=Target(connection=WSConnection(host, port)))
    define_proto_static(session)
    session.fuzz()

def define_proto_static(session):
    """Same protocol, using the static definition style."""
    s_initialize("websocket")
    s_static("{")\n''')
    fuzz.close()
    
def write_close():
    fuzz = open(filename, "a")
    fuzz.write('''    s_static("}")

    session.connect(s_get("websocket"))

if __name__ == "__main__":
    main()
''')
    fuzz.close()

gen()
