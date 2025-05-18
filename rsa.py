import random

def gcd_euclidean(a, b):
    while b != 0: 
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    old_r, r = a, b 
    old_x, x = 1, 0
    old_y, y = 0, 1 

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    
    return old_r, old_x, old_y

def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus 

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        
        base = (base * base) % modulus
        exponent //= 2
    return result

def is_prime_miller_rabin(n, k_bases):
    if n < 2:
        return False 
    if n == 2 or n == 3:
        return True 
    if n % 2 == 0:
        return False

    #(2^s) * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2 
        s += 1 

    for a in k_bases:
        if a >= n:
            continue 

        #(a^d) % n.
        x = modular_exponentiation(a, d, n) 
        
        if x == 1 or x == n - 1:
            continue
        
        # x^(2^r) % n == n-1
        is_composite_for_this_base = True
        for _ in range(s - 1): 
            x = modular_exponentiation(x, 2, n) # x = (x^2) % n
            if x == n - 1:
                is_composite_for_this_base = False
                break 

        if is_composite_for_this_base:
            return False

    return True

def generate_prime(max_value, bases):
    while True: 
        num = random.randint(3, max_value)
        if num % 2 == 0: 
            num += 1 

        if is_prime_miller_rabin(num, bases): 
            return num

def get_public_exponent(phi_n):
    while True:
        e = random.randint(2, phi_n - 1) 
        if gcd_euclidean(e, phi_n) == 1:
            return e

def get_private_exponent(e, phi_n):
    # d * e = 1 (mod phi_n)
    # e * x + phi_n * y = gcd(e, phi_n).
    # e * x = 1 (mod phi_n). 
    gcd_val, x, _ = extended_gcd(e, phi_n)

    if gcd_val != 1:
        raise ValueError("Moduláris inverz nem létezik. 'e' és 'phi_n' relatív prímeknek kell lenniük.")
    
    return x % phi_n

def encrypt_rsa(message, public_exponent, modulus_n):
    return modular_exponentiation(message, public_exponent, modulus_n)

def decrypt_rsa_crt(ciphertext, private_exponent, p_prime, q_prime):
    #c1 = titkosított_üzenet ^ (d mod (p-1)) mod p
    c1 = modular_exponentiation(ciphertext, private_exponent % (p_prime - 1), p_prime)
    
    #c2 = titkosított_üzenet ^ (d mod (q-1)) mod q
    c2 = modular_exponentiation(ciphertext, private_exponent % (q_prime - 1), q_prime)

    # N = p * q
    modulus_n = p_prime * q_prime

    # M1 = N / p = q
    m1_val = q_prime
    # M2 = N / q = p
    m2_val = p_prime

    # m1_val * y1 = 1 (mod m2_val)
    # m2_val * y2 = 1 (mod m1_val)
    
    gcd_val, inv_q_mod_p, inv_p_mod_q = extended_gcd(q_prime, p_prime)

    # üzenet = (c1 * M1 * y1 + c2 * M2 * y2) % N
    decrypted_message = (c1 * m1_val * inv_q_mod_p + c2 * m2_val * inv_p_mod_q) % modulus_n
    
    if decrypted_message < 0:
        decrypted_message += modulus_n
        
    return decrypted_message

def sign_message(message, private_exponent, p_prime, q_prime):

    return decrypt_rsa_crt(message, private_exponent, p_prime, q_prime)

def verify_signature(signature, public_exponent, modulus_n):
    return encrypt_rsa(signature, public_exponent, modulus_n)

def main():
    print("--- RSA Titkosítás és Digitális Aláírás Bemutató ---")

    min_prime_value = 100
    max_prime_value = 1000
    miller_rabin_bases = [2, 3, 5, 7, 11, 13, 17]
    
    while True:
        p = generate_prime(max_prime_value, miller_rabin_bases)
        q = generate_prime(max_prime_value, miller_rabin_bases)
        
        if p != q and p > min_prime_value and q > min_prime_value:
            break
    
    print(f"\nGenerált prím p: {p}")
    print(f"Generált prím q: {q}")

    # n = p * q 
    modulus_n = p * q
    print(f"Modulus n (p * q): {modulus_n}")

    #phi(n) = (p-1) * (q-1)
    phi_n = (p - 1) * (q - 1)
    print(f"Phi(n) ((p-1)*(q-1)): {phi_n}")

    public_exponent_e = get_public_exponent(phi_n)
    print(f"Nyilvános kitevő e: {public_exponent_e}")

    private_exponent_d = get_private_exponent(public_exponent_e, phi_n)
    print(f"Titkos kitevő d: {private_exponent_d}")

    # A nyilvános kulcs (n, e)
    public_key = (modulus_n, public_exponent_e)
    private_key_full = (modulus_n, private_exponent_d, p, q) # A CRT-hez

    print(f"\nRSA Nyilvános Kulcs (n, e): {public_key}")
    print(f"RSA Titkos Kulcs (n, d, p, q): {private_key_full}")

    print("\n--- RSA Titkosítás és Visszafejtés ---")

    original_message = 23
    print(f"Eredeti Üzenet (m): {original_message}")

    if original_message >= modulus_n:
        print(f"Figyelem: Az üzenet {original_message} túl nagy a modulushoz {modulus_n}. Válasszon kisebb üzenetet.")
        return

    # Titkosított Üzenet = (üzenet ^ e) % n
    ciphertext = encrypt_rsa(original_message, public_exponent_e, modulus_n)
    print(f"Titkosított Üzenet (c): {ciphertext}")

    # Visszafejtett Üzenet = (titkosított_üzenet ^ d) % n
    decrypted_message = decrypt_rsa_crt(ciphertext, private_exponent_d, p, q)
    print(f"Visszafejtett Üzenet: {decrypted_message}")


    # Aláírás = (üzenet ^ d) % n
    message_to_sign = 23
    print(f"Aláírandó Üzenet (m): {message_to_sign}")
    
    digital_signature = sign_message(message_to_sign, private_exponent_d, p, q)
    print(f"Digitális Aláírás (s): {digital_signature}")

    
    # Ellenőrzött Üzenet = (aláírás ^ e) % n
    verified_message = verify_signature(digital_signature, public_exponent_e, modulus_n)
    print(f"Ellenőrzött Üzenet (m'): {verified_message}")


if __name__ == "__main__":
    main()
