# Python3 BooFuzz Websockets fuzzer with Websocket Connection Implementation.

* boo-gen.py - fuzzer script generator from websocket's JSON.
* websocket_connection.py -  BooFuzz Websocket Connection Implementation.
* ws-fuzzer.py - sample of BooFuzz Websockets fuzzer.
* ws-request.txt - sample of Websockets JSON message.

## Usage

* (Simple) Use boo-gen.py to generate ws.py with fuzzer script
* (Harder) Write your own Websockets fuzzer using websocket_connection.py and ws-fuzzer.py as a sample.

## Boo-Gen Websockets Version Usage

`boo-gen.py ws-request.txt <-f output filename(optional)>`

### Options

* `-s` - host with path and protocol, for example wss://test.com/ws
* `-p` - disables proxy requests via ZAP or Burp (localhost:8080 default - can be changed in websocket_connection.py)
* `-x` - additional headers (useful for Cookies and etc)
* `-y` - silent mode Yes for all fields

### Examples

`boo-gen.py ws-request.txt -f ws.py`

`boo-gen.py -s wss://test.com/ws -x "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0" ws-request.txt`

## Links

* [BooFuzz](https://github.com/jtpereyda/boofuzz)
* [Boo-Gen HTTP Version](https://github.com/h0mbre/CTP-OSCE/tree/master/Boo-Gen)
