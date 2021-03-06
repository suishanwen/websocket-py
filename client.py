import websocket
import datetime
import time
import threading

try:
    import thread
except ImportError:
    import _thread as thread


def on_message(ws, message):
    print(message)


def on_error(ws, error):
    print(error)


def on_close(ws):
    print("### closed ###")


def on_open(ws):
    print("### open ###")
    # threading.Thread(target=send_data, args=(ws,)).start()


def send_data(ws):
    while True:
        ws.send('{"pong":"1"}')
        time.sleep(10)


if __name__ == "__main__":
    websocket.enableTrace(True)
    ws = websocket.WebSocketApp("ws://bitcoinrobot.cn:9090/",
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close,
                               )
    ws.on_open = on_open
    ws.run_forever()
