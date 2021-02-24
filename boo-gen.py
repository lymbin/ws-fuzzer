#!/usr/bin/python3
# This file is a part of Websockets BooFuzz Fuzzer
# From Websocket's JSON message BooFuzz Fuzzer File Generator

import argparse
import json

parser = argparse.ArgumentParser(add_help=True)
parser.add_argument("request", type=str, help="request template to fuzz")
parser.add_argument("-f", "--filename", default="ws.py", type=str, nargs="?", help="select name of fuzzing script (default is ws.py)", metavar='filename')
parser.add_argument("-s", "--host", default="wss://test.com/ws", type=str, nargs="?", help="host to fuzz", metavar='host')
parser.add_argument("-p", "--proxy", help="Off proxy requests via ZAP or Burp (localhost:8080)", action="store_false")
parser.add_argument("-y", "--yes", help="Yes for all (silent mode yes)", action="store_true")
parser.add_argument("-x", "--header", help="Additional Headers", type=str)

args = parser.parse_args()
request = args.request
filename = args.filename
host = args.host
headers = args.header
yes = args.yes

with open(request) as json_file:
    contents = json.load(json_file)

def gen():
    print("Generating %s from %s" % (filename, request))
    if headers is not None:
        print("Headers: %s" % (headers))
    if args.proxy:
        print("Proxy: on (used default localhost:8080)")
    if not args.proxy:
        print("Proxy: off")
    write_init()
    print("Found next data fields")
    print("--------------------------")
    gen_from_dict(contents)
    print("--------------------------")
    write_close()
    print("Saved results in %s" % (filename))
    print("To start fuzz run python3 %s" % (filename))

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
            print("Found \"%s: %s\"" % (x, dictionary[x]))
            if yes:
                fuzzs = open(filename, "a")
                fuzzs.write('''    s_delim("\\"", fuzzable=False)
    s_string("''' + dictionary[x] + '''")
    s_delim("\\"", fuzzable=False)\n''')
                fuzzs.close()
            else:
                makes = input('Make it fuzzable (string)? y/n(default)')
                if makes.lower() == 'yes' or makes.lower() == 'y':
                    fuzzs = open(filename, "a")
                    fuzzs.write('''    s_delim("\\"", fuzzable=False)
    s_string("''' + dictionary[x] + '''")
    s_delim("\\"", fuzzable=False)\n''')
                    fuzzs.close()
                else:
                    fuzzs = open(filename, "a")
                    fuzzs.write('''    s_delim("\\"", fuzzable=False)
    s_string("''' + dictionary[x] + '''", fuzzable=False)
    s_delim("\\"", fuzzable=False)\n''')
                    fuzzs.close()
        elif type(dictionary[x]) is int:
            print("Found \"%s: %d\"" % (x, dictionary[x]))
            if yes:
                fuzzi = open(filename, "a")
                fuzzi.write('''    s_int(''' + str(dictionary[x]) + ''', output_format="ascii")\n''')
                fuzzi.close()
            else:
                makei = input('Make it fuzzable (int)? y/n(default)')
                if makei.lower() == 'yes' or makei.lower() == 'y':
                    fuzzi = open(filename, "a")
                    fuzzi.write('''    s_int(''' + str(dictionary[x]) + ''', output_format="ascii")\n''')
                    fuzzi.close()
                else:
                    fuzzi = open(filename, "a")
                    fuzzi.write('''    s_int(''' + str(dictionary[x]) + ''', output_format="ascii", fuzzable=False)\n''')
                    fuzzi.close()
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
    port = 443 # whatever port
    ''')
    if args.proxy:
        fuzz.write('''    
    proxy = True''')
    else:
        fuzz.write('''    
    proxy = False''')
    if headers is not None:
        fuzz.write('''
    header_str = "''' + headers + '''"
    headers = header_str.split(", ")''')
    fuzz.write('''
    """ Create new WSConnection session. """
    session = Session(target=Target(connection=WSConnection(host, port, proxy, headers)))
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
