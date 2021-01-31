# BooFuzz Websockets fuzzer with Websocket Connection Implementation.

* boo-gen.py - fuzzer script generator from websocket's JSON.
* websocket_connection.py -  BooFuzz Websocket Connection Implementation.
* ws-fuzzer.py - sample of BooFuzz Websockets fuzzer.
* ws-request.txt - sample of Websockets JSON message.

## Usage

* (Simple) Use boo-gen.py to generate ws.py with fuzzer script
* (Harder) Write your own Websockets fuzzer using websocket_connection.py and ws-fuzzer.py as a sample.

## Boo-Gen Websockets Version Usage

`boo-gen.py ws-request.txt <-f output filename(optional)>`

### Examples

`boo-gen.py ws-request.txt -f ws.py`

## Links

[BooFuzz](https://github.com/jtpereyda/boofuzz)
[Boo-Gen HTTP Version](https://github.com/h0mbre/CTP-OSCE/tree/master/Boo-Gen)
