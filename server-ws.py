import socket
import base64
import hashlib
import re
import threading
import time, struct
import subprocess
from logger import Logger

HOST = "0.0.0.0"
PORT = 9090
MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
HANDSHAKE_STRING = "HTTP/1.1 101 Switching Protocols\r\n" \
                   "Upgrade:websocket\r\n" \
                   "Connection: Upgrade\r\n" \
                   "Sec-WebSocket-Accept: {1}\r\n" \
                   "WebSocket-Location: ws://{2}/chat\r\n" \
                   "WebSocket-Protocol:chat\r\n\r\n"
online_count = 0


def recv_data(clientSocket):
    while True:
        Logger.info("recving...")
        try:
            info = clientSocket.recv(2048)
            if not info:
                return
        except:
            Logger.info("recv exit!")
            return
        else:
            # Logger.info(info)
            code_len = info[1] & 0x7f
            if code_len == 0x7e:
                extend_payload_len = info[2:4]
                mask = info[4:8]
                decoded = info[8:]
            elif code_len == 0x7f:
                extend_payload_len = info[2:10]
                mask = info[10:14]
                decoded = info[14:]
            else:
                extend_payload_len = None
                mask = info[2:6]
                decoded = info[6:]
            bytes_list = bytearray()
            # Logger.info(mask)
            # Logger.info(decoded)
            for i in range(len(decoded)):
                chunk = decoded[i] ^ mask[i % 4]
                bytes_list.append(chunk)
            raw_str = str(bytes_list, encoding="utf-8")
            # data = json.loads(raw_str)
            send(clientSocket, raw_str)
            time.sleep(1)


def send(clientSocket, data):
    token = b'\x81'
    length = len(data.encode())
    if length <= 125:
        token += struct.pack('B', length)
    elif length <= 0xFFFF:
        token += struct.pack('!BH', 126, length)
    else:
        token += struct.pack('!BQ', 127, length)
    data = token + data.encode()
    clientSocket.send(data)


def send_data(clientSocket, socket_id):
    global online_count
    online_count += 1
    if socket_id == 0:
        cmd = "tail -f /home/balance/ok/nohup.out"
    else:
        cmd = "tail -f /home/netUseMonitor/monitor.log"
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    _exit = False
    while not _exit:
        line = popen.stdout.readline().strip()  # 获取内容
        if line:
            data = bytes.decode(line, encoding="utf-8")
            try:
                send(clientSocket, data)
            except Exception:
                popen.kill()
                online_count -= 1
                Logger.info("用户退出，当前链接共%d人!", online_count)
                _exit = True


def handshake(serverSocket):
    clientSocket, addressInfo = serverSocket.accept()
    Logger.info("用户接入！")
    request = clientSocket.recv(2048)
    # Logger.info("request:" + request.decode())
    # 获取Sec-WebSocket-Key
    ret = re.search(r"Sec-WebSocket-Key: (.*==)", str(request.decode()), re.IGNORECASE)
    if ret:
        key = ret.group(1)
    else:
        Logger.error("Sec-WebSocket-Key not found , return !")
        return
    # socket id
    ret = re.search(r"ID: (\d)", str(request.decode()))
    socket_id = 1
    if ret:
        socket_id = int(ret.group(1))
    Logger.info("通道%d,已连接...", socket_id)
    Sec_WebSocket_Key = key + MAGIC_STRING
    # Logger.info("key ", Sec_WebSocket_Key)
    # # 将Sec-WebSocket-Key先进行sha1加密,转成二进制后在使用base64加密
    response_key = base64.b64encode(hashlib.sha1(bytes(Sec_WebSocket_Key, encoding="utf8")).digest())
    response_key_str = str(response_key)
    response_key_str = response_key_str[2:30]
    # Logger.info(response_key_str)
    # # 构建websocket返回数据
    response = HANDSHAKE_STRING.replace("{1}", response_key_str).replace("{2}", HOST + ":" + str(PORT))
    clientSocket.send(response.encode())
    # t1 = threading.Thread(target=recv_data, args=(clientSocket,))
    # t1.start()
    t2 = threading.Thread(target=send_data, args=(clientSocket, socket_id))
    t2.start()


def main():
    # 创建基于tcp的服务器
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host = (HOST, PORT)
    serverSocket.bind(host)
    serverSocket.listen(128)
    Logger.info("服务器运行, 等待用户链接")
    # 调用监听
    while True:
        handshake(serverSocket)


if __name__ == "__main__":
    main()
