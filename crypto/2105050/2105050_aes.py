import os
from pathlib import Path
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
from PIL import Image

BLOCK_SIZE = 16   

def prepare_key_bytes(user_provided_key_bytes, target_key_length_bytes): 
    ## jodi target theke choto size er KEY dei manually
    if len(user_provided_key_bytes) < target_key_length_bytes:
        missing_byte_count = target_key_length_bytes - len(user_provided_key_bytes)
        return user_provided_key_bytes + bytes(missing_byte_count)
    return user_provided_key_bytes[:target_key_length_bytes]


def expand_key(key_bytes):
    key_length_bytes = len(key_bytes)

    if key_length_bytes not in (16, 24, 32):
        key_bytes = prepare_key_bytes(key_bytes, target_key_length_bytes=16)
        key_length_bytes = len(key_bytes)

    words_in_key = key_length_bytes // 4
    number_of_rounds = words_in_key + 6
    total_words_needed = 4 * (number_of_rounds + 1) # w0,w1,w2,....w43

    key_schedule_words = []

    for byte_index in range(0, key_length_bytes, 4):
        word = list(key_bytes[byte_index:byte_index + 4])
        key_schedule_words.append(word) # w0,w1,w2,w3 append kora done

    for word_index in range(words_in_key, total_words_needed):
        previous_word = key_schedule_words[word_index - 1].copy()

        if word_index % words_in_key == 0:
            previous_word = left_shift_word(previous_word)
            previous_word = byte_subtitution(previous_word)
            previous_word = add_round_constant(previous_word, word_index // words_in_key) #g[w3] produce krlam for w4 finding in aes 128
        elif words_in_key > 6 and word_index % words_in_key == 4:
            previous_word = byte_subtitution(previous_word)

        word_from_back = key_schedule_words[word_index - words_in_key]
        new_word = []
        for byte_index in range(4):
            new_byte = previous_word[byte_index] ^ word_from_back[byte_index] #w[5] = w[4]^w[1]
            new_word.append(new_byte)

        key_schedule_words.append(new_word) 

    round_keys = []
    for word_index in range(0, total_words_needed, 4):
        round_key_bytes = []
        for word_offset in range(4):
            round_key_bytes.extend(key_schedule_words[word_index + word_offset])
        round_keys.append(round_key_bytes)

    return round_keys
    
    


# WORD = 4bytes
def left_shift_word(word):
    #print("word before left shift: ", word)
    final_word = word[1:]+word[:1]
    #print("word after left shift: ", final_word)
    return final_word

    
    
    



def byte_subtitution(word):
    #print("word before substitution: ", word)
    for b in range(len(word)):
        word[b] = Sbox[word[b]]
    #print("word after substitution: ", word)
    return word
    

def add_round_constant(word, round_num):
    #print("word before adding round constant: ", word)
    word[0] = word[0] ^ Rcon[round_num]
    #print("word after adding round constant: ", word)
    return word



def bytes_to_state(block16):
    if len(block16) != 16:
        raise ValueError("Block must be 16 bytes long.")
    
    state = [[0] * 4 for _ in range(4)]  # Initialize a 4x4 matrix
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = block16[i]
    
    return state





def state_to_bytes(state):
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("State must be a 4x4 matrix.")
    
    block16 = bytearray(16)
    for col in range(4):
        for row in range(4):
            block16[col * 4 + row] = state[row][col]
    
    return bytes(block16)




def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = Sbox[state[r][c]]
    return state


def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = InvSbox[state[r][c]]
    return state



def shift_rows(state):
    for r in range(4):
        state[r] = state[r][r:] + state[r][:r]
    return state



def inv_shift_rows(state):
    for r in range(4):
        state[r] = state[r][-r:] + state[r][:-r]
    return state




def mix_columns(state):
    for c in range(4):
        # col = [state[r][c] for r in range(4)]
        col = []
        for r in range(4):
            col.append(state[r][c])

        new_col = [0] * 4
        for r in range(4):
            new_col[r] = (gf_mult(Mixer[r][0], col[0]) ^
                          gf_mult(Mixer[r][1], col[1]) ^
                          gf_mult(Mixer[r][2], col[2]) ^
                          gf_mult(Mixer[r][3], col[3]))
        for r in range(4):
            state[r][c] = new_col[r]
    return state


def inv_mix_columns(state):
    for c in range(4):
        # col = [state[r][c] for r in range(4)]
        col = []
        for r in range(4):
            col.append(state[r][c])
        new_col = [0] * 4
        for r in range(4):
            new_col[r] = (gf_mult(InvMixer[r][0], col[0]) ^
                          gf_mult(InvMixer[r][1], col[1]) ^
                          gf_mult(InvMixer[r][2], col[2]) ^
                          gf_mult(InvMixer[r][3], col[3]))
        for r in range(4):
            state[r][c] = new_col[r]
    return state



def add_round_key(state, round_key):
    if len(round_key) != 16:
        raise ValueError("Round key must be 16 bytes long.")
    
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[c * 4 + r]
    
    return state

# =======encrypt decrupt

def encrypt_block(block16, round_keys):
    no_of_rounds = len(round_keys) - 1

    
    state = bytes_to_state(block16)
    
  
    state = add_round_key(state, round_keys[0])
    
  
    for round_num in range(1, no_of_rounds):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    
   
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[no_of_rounds])
    

    return state_to_bytes(state)


def decrypt_block(block16, round_keys):
    no_of_rounds = len(round_keys) - 1


    state = bytes_to_state(block16)

    state = add_round_key(state, round_keys[no_of_rounds])
    

    for round_num in range(no_of_rounds - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)
    
    
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    
   
    return state_to_bytes(state)

# padding

def pad_pkcs7(hexdata):
 
    data = hexdata
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    if pad_len == 0:
        pad_len = BLOCK_SIZE
    padded_data = data + bytes([pad_len] * pad_len)
    return padded_data

    

def unpad_pkcs7(padded_data):
    pad_len = padded_data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if padded_data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return padded_data[:-pad_len]

# ---------------------------------------------------------------------------
# Modes
def ecb_encrypt(plaintext_bytes, round_keys):
    padded_plaintext = pad_pkcs7(plaintext_bytes)
    ciphertext = bytearray()

    for i in range(0, len(padded_plaintext), BLOCK_SIZE):
        block = padded_plaintext[i:i + BLOCK_SIZE]
        encrypted_block = encrypt_block(block, round_keys)
        ciphertext.extend(encrypted_block)

    return bytes(ciphertext)


def ecb_decrypt(cipher_bytes, round_keys):
    if len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes.")
    
    plaintext = bytearray()

    for i in range(0, len(cipher_bytes), BLOCK_SIZE):
        block = cipher_bytes[i:i + BLOCK_SIZE]
        decrypted_block = decrypt_block(block, round_keys)
        plaintext.extend(decrypted_block)

    return unpad_pkcs7(plaintext)


def cbc_encrypt(plaintext_bytes, round_keys, iv=None):
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    elif len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes long.")
    
    padded_plaintext = pad_pkcs7(plaintext_bytes)
    ciphertext = bytearray(iv)  # Start korbo with the IV

    previous_block = iv
    for i in range(0, len(padded_plaintext), BLOCK_SIZE):
        block = padded_plaintext[i:i + BLOCK_SIZE]
        # XOR with previous cipher block (or IV for the first block) very important !!
        xor_block = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block = encrypt_block(xor_block, round_keys)
        ciphertext.extend(encrypted_block)
        previous_block = encrypted_block  # Update previous block...and so on

    return bytes(ciphertext)


def cbc_decrypt(cipher_bytes, round_keys):
    if len(cipher_bytes) < BLOCK_SIZE or len(cipher_bytes) % BLOCK_SIZE != 0:
      raise ValueError("Ciphertext length must be at least 16 bytes and a multiple of 16 bytes.")
    
    #ber koro the first 16 bytes as the IV
    iv = cipher_bytes[:BLOCK_SIZE]
    ciphertext_blocks = cipher_bytes[BLOCK_SIZE:]

    plaintext = bytearray()
    previous_block = iv

    for i in range(0, len(ciphertext_blocks), BLOCK_SIZE):
        block = ciphertext_blocks[i:i + BLOCK_SIZE]
        decrypted_block = decrypt_block(block, round_keys)
        xor_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
        plaintext.extend(xor_block)
        previous_block = block

    return unpad_pkcs7(plaintext)

# helpers

def str_to_bytes(text):
    return text.encode("utf-8")


def bytes_to_hex(data):
    return data.hex()



def bytes_to_ascii(data):
    return data.decode(errors="replace")

def format_hex_to_print(hexdata):
    spaced_hex = ' '.join(hexdata[i:i+2] for i in range(0, len(hexdata), 2))
    return spaced_hex
    

def format_ascii_to_print(asciidata):
    return asciidata



def run_demo (key, plaintext, mode):
  import time

  print(f"======================= AES / {mode} =====================")
  print("\nKey:")
  print(f"In ASCII: {key}")
  print(f"In HEX: {format_hex_to_print(bytes_to_hex(str_to_bytes(key)))}")
  print("\nPlain Text:")
  print(f"In ASCII: {plaintext}")
  print(f"In HEX: {format_hex_to_print(bytes_to_hex(str_to_bytes(plaintext)))}")
  print(f"In ASCII (After Padding): {bytes_to_ascii(pad_pkcs7(str_to_bytes(plaintext)))}")
  print(f"In HEX (After Padding): {format_hex_to_print(bytes_to_hex(pad_pkcs7(str_to_bytes(plaintext))))}")

  print("\nCiphered Text:")
  if mode == "CBC":
    print("(IV is the first 16 bytes, followed by the actual ciphertext)")

  key_schedule_start_time = time.time()
  round_keys = expand_key(str_to_bytes(key))
  key_schedule_time_ms = (time.time() - key_schedule_start_time) * 1000
#   print("All Round Keys:")
#   for i, rk in enumerate(round_keys):
#     print(f"Round {i}: {format_hex_to_print(bytes_to_hex(bytes(rk)))}")

  # encrypt the plaintext
  if mode == "ECB":
    encryption_start_time = time.time()
    cipher_bytes = ecb_encrypt(str_to_bytes(plaintext), round_keys)
    encryption_time_ms = (time.time() - encryption_start_time) * 1000
    print(f"In HEX: {format_hex_to_print(bytes_to_hex(cipher_bytes))}")
    print(f"In ASCII: {bytes_to_ascii(cipher_bytes)}")

    decryption_start_time = time.time()
    padded_before_unpadding = bytearray()
    for i in range(0, len(cipher_bytes), BLOCK_SIZE):
      padded_before_unpadding.extend(decrypt_block(cipher_bytes[i:i + BLOCK_SIZE], round_keys))
    padded_before_unpadding = bytes(padded_before_unpadding)
    decrypted_bytes = unpad_pkcs7(padded_before_unpadding)
    decryption_time_ms = (time.time() - decryption_start_time) * 1000

    print("\nDeciphered Text:")
    print("Before Unpadding:")
    print(f"In HEX: {format_hex_to_print(bytes_to_hex(padded_before_unpadding))}")
    print(f"In ASCII: {bytes_to_ascii(padded_before_unpadding)}")
    print("After Unpadding:")
    print(f"In ASCII: {bytes_to_ascii(decrypted_bytes)}")
    print(f"In HEX: {format_hex_to_print(bytes_to_hex(decrypted_bytes))}")

  elif mode == "CBC":
    encryption_start_time = time.time()
    cipher_bytes = cbc_encrypt(str_to_bytes(plaintext), round_keys)
    encryption_time_ms = (time.time() - encryption_start_time) * 1000
    print(f"In HEX: {format_hex_to_print(bytes_to_hex(cipher_bytes))}")
    print(f"In ASCII: {bytes_to_ascii(cipher_bytes)}")

    decryption_start_time = time.time()
    iv = cipher_bytes[:BLOCK_SIZE]
    ciphertext_blocks = cipher_bytes[BLOCK_SIZE:]
    padded_before_unpadding = bytearray()
    previous_block = iv
    for i in range(0, len(ciphertext_blocks), BLOCK_SIZE):
      block = ciphertext_blocks[i:i + BLOCK_SIZE]
      decrypted_block = decrypt_block(block, round_keys)
      xor_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
      padded_before_unpadding.extend(xor_block)
      previous_block = block
    padded_before_unpadding = bytes(padded_before_unpadding)
    decrypted_bytes = unpad_pkcs7(padded_before_unpadding)
    decryption_time_ms = (time.time() - decryption_start_time) * 1000

    print("\nDeciphered Text:")
    print("Before Unpadding:")
    print(f"In HEX: {format_hex_to_print(bytes_to_hex(padded_before_unpadding))}")
    print(f"In ASCII: {bytes_to_ascii(padded_before_unpadding)}")
    print("After Unpadding:")
    print(f"In ASCII: {bytes_to_ascii(decrypted_bytes)}")
    print(f"In HEX: {format_hex_to_print(bytes_to_hex(decrypted_bytes))}")

  else:
    raise ValueError("Unsupported mode. Use 'ECB' or 'CBC'.")

  print("\nExecution Time Details:")
  print(f"Key Schedule Time: {key_schedule_time_ms} ms")
  print(f"Encryption Time: {encryption_time_ms} ms")
  print(f"Decryption Time: {decryption_time_ms} ms")


def run_image_demo(key, image_path):
    image_bytes = Path(image_path).read_bytes()
    pixel_data_offset = int.from_bytes(image_bytes[10:14], byteorder="little")
    header_bytes = image_bytes[:pixel_data_offset]
    pixel_bytes = image_bytes[pixel_data_offset:]

    round_keys = expand_key(str_to_bytes(key))
    usable_length = (len(pixel_bytes) // BLOCK_SIZE) * BLOCK_SIZE
    leftover_tail_bytes = pixel_bytes[usable_length:]

    ecb_pixel_bytes = bytearray()
    for i in range(0, usable_length, BLOCK_SIZE):
        ecb_pixel_bytes.extend(encrypt_block(pixel_bytes[i:i + BLOCK_SIZE], round_keys))
    ecb_pixel_bytes = bytes(ecb_pixel_bytes) + leftover_tail_bytes

    cbc_pixel_bytes = bytearray()
    previous_block = bytes(BLOCK_SIZE)
    for i in range(0, usable_length, BLOCK_SIZE):
        block = pixel_bytes[i:i + BLOCK_SIZE]
        xor_block = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block = encrypt_block(xor_block, round_keys)
        cbc_pixel_bytes.extend(encrypted_block)
        previous_block = encrypted_block
    cbc_pixel_bytes = bytes(cbc_pixel_bytes) + leftover_tail_bytes

    source_path = Path(image_path)
    output_directory = Path(__file__).resolve().parent
    ecb_path = output_directory / "2105050_image_ecb.bmp"
    cbc_path = output_directory / "2105050_image_cbc.bmp"
    side_by_side_path = output_directory / "2105050_image_ecb_vs_cbc.png"

    ecb_path.write_bytes(header_bytes + ecb_pixel_bytes)
    cbc_path.write_bytes(header_bytes + cbc_pixel_bytes)

    
    ecb_image = Image.open(ecb_path).convert("RGB")
    cbc_image = Image.open(cbc_path).convert("RGB")
    width, height = ecb_image.size
    gap = 10
    side_by_side = Image.new("RGB", (width * 2 + gap, height), color=(30, 30, 30))
    side_by_side.paste(ecb_image, (0, 0))
    side_by_side.paste(cbc_image, (width + gap, 0))
    side_by_side.save(side_by_side_path)

    print(f"Source image: {source_path} ({len(image_bytes)} bytes)")
    print(f"Pixel data: {len(pixel_bytes)} bytes, starting at header offset {len(header_bytes)}")
    print(f"ECB-encrypted BMP written to: {ecb_path}")
    print(f"CBC-encrypted BMP written to: {cbc_path}")
    print(f"Side-by-side comparison written to: {side_by_side_path}")


if __name__ == "__main__":
    key = "BUET CSE20 Batch"
    plaintext = "We need picnic"
    run_demo(key, plaintext, "ECB")
    #run_demo(key, plaintext, "CBC")

    #run_image_demo(key, "2105050_sample_small.bmp")



