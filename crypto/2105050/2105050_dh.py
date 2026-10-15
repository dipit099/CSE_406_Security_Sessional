
import random

random.seed(2105050)

KEY_SIZE_BITS = 128


_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                  59, 61, 67, 71, 73, 79, 83, 89, 97)


def is_probable_prime(n, rounds=40):
   
    if n < 2:
        return False

    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False


    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def _random_odd_candidate(bits):
    n = random.getrandbits(bits)
    n |= (1 << (bits - 1)) | 1 
    return n


def generate_prime(key_size_bits):
    while True:
        q = _random_odd_candidate(key_size_bits - 1)
        if not is_probable_prime(q):
            continue
        P = 2 * q + 1
        if P.bit_length() != key_size_bits:
            continue
        if is_probable_prime(P):
            print(f"Generated safe prime: P={P} (q={q})")
            return P, q




def generate_generator(P, q):
    while True:
        g = random.randint(2, P - 2)
        if pow(g, 2, P) == 1:
            continue
        if pow(g, q, P) == 1:
            continue
        print(f"Found generator: {g}")
        return g


def make_public_params(key_size_bits):
    P, q = generate_prime(key_size_bits)
    g = generate_generator(P, q)
    return P, g


def generate_private_public(P, g, key_size_bits):
    smallest_allowed_secret_value = 1 << (key_size_bits - 1)
    secret = random.randint(smallest_allowed_secret_value, P - 2)
    public = pow(g, secret, P)

    return secret, public




def shared_secret(their_public, my_secret, P):
    return pow(their_public, my_secret, P)


## WE DID THE HASH HERE !!!! YAY
def derive_aes_key(shared_secret, key_size_bits):
    # Convert the shared secret to bytes
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    # Hash the bytes of the shared secret using SHA-256
    import hashlib
    hash_digest = hashlib.sha256(shared_secret_bytes).digest()
    # Take the first k_bits/8 bytes of the digest as the AES key
    aes_key = hash_digest[:key_size_bits // 8]
    return aes_key


# Timing report 
def benchmark(key_size_bits, trials=5):
    import time
    total_time_A = 0
    total_time_B = 0
    total_time_s = 0

    for _ in range(trials):
        P, g = make_public_params(key_size_bits)

        # Measure time for Alice
        start_time_A = time.time()
        Ka, A = generate_private_public(P, g, key_size_bits)
        end_time_A = time.time()
        total_time_A += (end_time_A - start_time_A)

        # Measure time for Bob
        start_time_B = time.time()
        Kb, B = generate_private_public(P, g, key_size_bits)
        end_time_B = time.time()
        total_time_B += (end_time_B - start_time_B)

        # Measure time for shared secret computation
        start_time_s = time.time()
        s_Alice = shared_secret(B, Ka, P)
        s_Bob = shared_secret(A, Kb, P)
        end_time_s = time.time()
        total_time_s += (end_time_s - start_time_s)

        assert s_Alice == s_Bob, "Shared secrets do not match!"

    avg_time_A = total_time_A / trials
    avg_time_B = total_time_B / trials
    avg_time_s = total_time_s / trials

    return avg_time_A, avg_time_B, avg_time_s


def print_timing_table():
    print(f"{'Key Size (bits)':<20} {'Time for A (s)':<20} {'Time for B (s)':<20} {'Time for shared key s (s)':<30}")
    print("-" * 90)
    for k in [128, 192, 256]:
        avg_time_A, avg_time_B, avg_time_s = benchmark(k)
        print(f"{k:<20} {avg_time_A:<20.6f} {avg_time_B:<20.6f} {avg_time_s:<30.6f}")



if __name__ == "__main__":
    key_size_bits = KEY_SIZE_BITS
    P, g = make_public_params(key_size_bits)
    Ka, A = generate_private_public(P, g, key_size_bits)
    Kb, B = generate_private_public(P, g, key_size_bits)
    s_Alice = shared_secret(B, Ka, P)
    s_Bob = shared_secret(A, Kb, P)

    assert s_Alice == s_Bob, "Shared secrets do not match!"

    print(f"P: {P}")
    print(f"g: {g}")
    print(f"Alice's secret (Ka): {Ka}, public (A): {A}")
    print(f"Bob's secret (Kb): {Kb}, public (B): {B}")
    print(f"Shared secret (s): {s_Alice}")

    print_timing_table()