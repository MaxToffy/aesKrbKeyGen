import argparse

from binascii import unhexlify

from Crypto.Hash import MD4
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Protocol import KDF

AES256_CONSTANT = [0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4]
AES128_CONSTANT = AES256_CONSTANT[:16]
IV = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
ITERATION = 4096 # Active Directory default

def _create_des_key(key7):
    key = [
        key7[0] & 0xFE,
        ((key7[0] << 7) | (key7[1] >> 1)) & 0xFE,
        ((key7[1] << 6) | (key7[2] >> 2)) & 0xFE,
        ((key7[2] << 5) | (key7[3] >> 3)) & 0xFE,
        ((key7[3] << 4) | (key7[4] >> 4)) & 0xFE,
        ((key7[4] << 3) | (key7[5] >> 5)) & 0xFE,
        ((key7[5] << 2) | (key7[6] >> 6)) & 0xFE,
        (key7[6] << 1) & 0xFE,
    ]

    # Apply odd parity
    for i in range(8):
        b = key[i]
        parity = 1
        for j in range(7):
            parity ^= (b >> j) & 1
        key[i] |= parity

    return bytes(key)


def do_lm_hash(password: str) -> str:
    magic = b"KGS!@#$%"
    pw = password.upper().encode("ascii", "ignore")[:14]
    pw = pw.ljust(14, b"\x00")

    key1 = _create_des_key(pw[:7])
    key2 = _create_des_key(pw[7:])

    des1 = DES.new(key1, DES.MODE_ECB)
    des2 = DES.new(key2, DES.MODE_ECB)

    return (des1.encrypt(magic) + des2.encrypt(magic)).hex()

def do_nt_hash(password: str) -> str:
    h = MD4.new()
    h.update(password.encode("utf-16le"))
    return h.hexdigest()

def do_aes_256(aes_256_pbkdf2):
    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_1 = cipher.encrypt(bytes(AES256_CONSTANT))
    
    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_2 = cipher.encrypt(bytearray(key_1))
    
    aes_256_raw = key_1[:16] + key_2[:16]
    return aes_256_raw.hex()


def do_aes_128(aes_128_pbkdf2):
    cipher = AES.new(aes_128_pbkdf2, AES.MODE_CBC, bytes(IV))
    aes_128_raw = cipher.encrypt(bytes(AES128_CONSTANT))
    return aes_128_raw.hex()


def main():
    parser = argparse.ArgumentParser(description='Generate NTLM hashes and AES128/256 Kerberos keys for an AD account using a plaintext password', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-realm', type=str, help='Kerberos realm name', required=True)
    parser.add_argument('-user', type=str, help='Case sensitive sAMAccountName')
    parser.add_argument('-computer', type=str, help='FQDN hostname (ex: dc01.cerbere.local)')
    parser.add_argument('-pass', type=str, dest='password', help='Valid cleartext or hex account password', required=True)
    parser.add_argument("-i", type=int, help='Iterations to perform for PBKDF2', default=4096)


    args = parser.parse_args()

    realm = args.realm.upper()
    if args.computer:
        trustee = args.computer.replace('$', '') # ensure $ is not present in hostname
        salt = f'{realm}host{trustee.lower()}'
    elif args.user:
        salt = f'{realm}{args.user}'
    else:
        print("Computer or user required")
        exit()

    print(f'[*] Salt: {salt}')    
    
    try:
        password = unhexlify(args.password).decode('utf-16-le', 'replace')
    except:
        password = args.password

    salt_bytes = salt.encode('utf-8')


    aes_256_pbkdf2 = KDF.PBKDF2(password.encode('utf-8'), salt_bytes, 32, args.i)
    aes_128_pbkdf2 = aes_256_pbkdf2[:16]

    print()
    print(f"[+] LM Hash    : {do_lm_hash(password)}")
    print(f"[+] NT Hash    : {do_nt_hash(password)}")
    print(f'[+] AES128 Key : {do_aes_128(aes_128_pbkdf2)}')
    print(f'[+] AES256 Key : {do_aes_256(aes_256_pbkdf2)}')

if __name__ == '__main__':
    main()
