
import importlib
from importlib import util
from pathlib import Path

SEND_MODE = "MESSAGE"  
# "DOCUMENT" to send document.txt, "MESSAGE" to send message_text below
message_text = "Hello Bob, this is Alice sending a secret message over our DH+AES channel!"


def load_module(mod_filename, mod_alias):
    spec = importlib.util.spec_from_file_location(mod_alias, mod_filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def send_msg(sock, data_bytes):
    length = len(data_bytes)
    sock.sendall(length.to_bytes(4, byteorder='big') + data_bytes)


def recv_exactly(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket connection closed unexpectedly")
        data += packet
    return data

def recv_msg(sock):
    length_bytes = recv_exactly(sock, 4)
    length = int.from_bytes(length_bytes, byteorder='big')
    return recv_exactly(sock, length)


def main():
    aes = load_module("2105050_aes.py", "aes2105050")
    dh = load_module("2105050_dh.py", "dh2105050")
    key_size_bits = dh.KEY_SIZE_BITS
    input_file = Path("./document.txt")

    P, g = dh.make_public_params(key_size_bits)
    Ka, A = dh.generate_private_public(P, g, key_size_bits)

    import socket
    host = 'localhost'
    port = 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))

        send_msg(sock, str(P).encode())
        send_msg(sock, str(g).encode())
        send_msg(sock, str(A).encode())

        print(f"Connected to BOB on {host}:{port}")

        B_bytes = recv_msg(sock)
        B = int(B_bytes.decode())

        s = dh.shared_secret(B, Ka, P)
        key = dh.derive_aes_key(s, key_size_bits)

        send_msg(sock, b'READY')
        ready_signal = recv_msg(sock)
        if ready_signal != b'READY':
            raise ValueError("Did not receive READY signal from Bob")

        if SEND_MODE == "MESSAGE":
            plaintext_bytes = aes.str_to_bytes(message_text)
        else:
            plaintext_bytes = input_file.read_bytes()
        round_keys = aes.expand_key(key)
        ciphertext = aes.cbc_encrypt(plaintext_bytes, round_keys)

        send_msg(sock, ciphertext)

        print(f"AES Key (hex): {key.hex()}")
        if SEND_MODE == "MESSAGE":
            print(f"Sent message: {message_text!r} ({len(plaintext_bytes)} bytes)")
        else:
            print(f"Sent file: {input_file} ({len(plaintext_bytes)} bytes)")
       

if __name__ == "__main__":
    main()
