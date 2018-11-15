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
    threading.Thread(target=send_data, args=(ws,)).start()


def send_data(ws):
    print("thread send_data running")
    while True:
        ws.send("{pong:2}")
        time.sleep(10)


if __name__ == "__main__":
    websocket.enableTrace(True)
    ws = websocket.WebSocketApp("ws://127.0.0.1:9090/",
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close)
    ws.on_open = on_open
    ws.run_forever()
