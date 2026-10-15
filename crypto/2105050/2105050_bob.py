import importlib
from importlib import util
import socket
from pathlib import Path

def load_module(mod_filename, mod_alias):
    spec = importlib.util.spec_from_file_location(mod_alias, mod_filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



def send_msg(sock, data_bytes):
    length = len(data_bytes)
    sock.sendall(length.to_bytes(4, byteorder='big') + data_bytes)


def   recv_exactly(sock, n):
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
    output_file = Path("./recovered_document.txt")
    host = 'localhost'
    port = 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"BOB listening on {host}:{port}...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            P_bytes = recv_msg(conn)
            g_bytes = recv_msg(conn)
            A_bytes = recv_msg(conn)
            P = int(P_bytes.decode())
            g = int(g_bytes.decode())
            A = int(A_bytes.decode())
            print(f"Received P={P}, g={g}, A={A} from ALICE")
            Kb, B = dh.generate_private_public(P, g, key_size_bits)
            send_msg(conn, str(B).encode())
            print(f"Sent B={B} to ALICE")
            s = dh.shared_secret(A, Kb, P)
            key = dh.derive_aes_key(s, key_size_bits)
            print(f"Derived shared secret s={s}, AES key={key.hex()}")
            ready_signal = recv_msg(conn)
            if ready_signal != b'READY':
                raise ValueError("Did not receive READY signal from ALICE")
            send_msg(conn, b'READY')
            ciphertext = recv_msg(conn)
            round_keys = aes.expand_key(key)
            plaintext = aes.cbc_decrypt(ciphertext, round_keys)
            output_file.write_bytes(plaintext)
            print(f"Received ciphertext: {ciphertext.hex()}")
            print(f"Recovered file written to: {output_file} ({len(plaintext)} bytes)")
            #print(f"Recovered message: {aes.bytes_to_ascii(plaintext)}")






if __name__ == "__main__":
    main()
