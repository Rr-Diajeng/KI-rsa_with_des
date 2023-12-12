import socket
import threading
import math
import json
import random
import time

from des import DES
from bagian import Bagian

des = DES()
bagian = Bagian()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((socket.gethostname(), 5000))
server.listen()

clients = []
aliases = []
pub_keys = {}

def generateKey(key):
    key = key.upper()

    key = bagian.hex2bin(key)

    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    key = des.permute(key, keyp, 56)

    shift_table = [1, 1, 2, 2,
                2, 2, 2, 2,
                1, 2, 2, 2,
                2, 2, 2, 1]

    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

    left = key[0:28]  # rkb for RoundKeys in binary
    right = key[28:56]  # rk for RoundKeys in hexadecimal

    rkb = []
    rk = []
    for i in range(0, 16):
        left = des.shift_left(left, shift_table[i])
        right = des.shift_left(right, shift_table[i])

        combine_str = left + right

        round_key = des.permute(combine_str, key_comp, 48)

        rkb.append(round_key)
        rk.append(bagian.bin2hex(round_key))

    return rk, rkb

def encrypt_des(text, key):
    rk, rkb = generateKey(key)

    message_text = bagian.bin2alpha(des.encrypt(text, rkb, rk))
    return message_text

def decrypt_des(text, key, banyak_kalimat):
    rk, rkb = generateKey(key)

    rkb_rev = rkb[::-1]
    rk_rev = rk[::-1]
    text_alpha = bagian.bin2alpha(des.encrypt(text, rkb_rev, rk_rev))
    
    hasil_decrypt= text_alpha[0:banyak_kalimat].lower()

    return hasil_decrypt

def generate_random_hex(length=16):
    # Menghasilkan bilangan bulat acak dalam rentang yang sesuai dengan panjang heksadesimal yang diinginkan
    random_number = random.randint(0, 16**length - 1)
    # Mengonversi bilangan bulat menjadi heksadesimal dan menghilangkan '0x' di awal
    random_hex = format(random_number, 'x').zfill(length)
    return random_hex

def encrypt_each_character(session_key_array, e, n):
    encrypted_array = []

    for char in session_key_array:
        # Mengonversi karakter menjadi nilai ASCII
        ascii_value = ord(char)

        # Mengenkripsi nilai ASCII
        encrypted_char = encrypt_rsa(ascii_value, e, n)

        # Menambahkan hasil enkripsi ke array
        encrypted_array.append(encrypted_char)

    return encrypted_array

def rsa_key(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 2
    while e < phi:
        if math.gcd(e, phi) == 1:
            break
        else:
            e += 1
    k = 2
    d = ((k * phi) + 1) // e

    pub = (e, n)
    priv = (d, n)

    return pub, priv, e, d, n

def text_to_int(text):
    return int.from_bytes(text.encode('utf-8'), 'big')

def encrypt_rsa(message, e, n):
    # RSA encryption: c = (message ^ e) % n
    return pow(message, e, n)

def decrypt_rsa(ciphertext, d, n):
    # RSA decryption: m = (ciphertext ^ d) % n
    return pow(ciphertext, d, n)

p = 503
q = 587
full_pub, full_priv, pub_key, priv_key, nn = rsa_key(p, q)

client_n = None
client_e = None
encrypted_n1 = None 
encrypted_id = None
decrypted_n1 = None
encrypt3_n2 = None

N2 = 321

def handle_client(client):
    global client_n, client_e, encrypted_n1, encrypted_id, decrypted_n1, encrypt3_n2
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message == 'share':
                # Receive client's public key
                client_pub_key_json = client.recv(1024).decode('utf-8')
                alias = aliases[clients.index(client)]
                pub_keys[alias] = json.loads(client_pub_key_json)
                print('Received public key from {}: {}'.format(alias, pub_keys[alias]))
                client_n = pub_keys[alias]['n']
                client_e = pub_keys[alias]['e']

                time.sleep(2)
                pub_key_json = json.dumps({'e': full_pub[0], 'n': full_pub[1]})
                client.send(pub_key_json.encode('utf-8'))
            
            elif message == 'encrypt1':
                time.sleep(2)
                encryptedmessaged = client.recv(1024).decode('utf-8')
                hasilencrypt = json.loads(encryptedmessaged)
                print('Encrypted message: {}'.format(encryptedmessaged))
                encrypted_n1 = hasilencrypt['N1']
                encrypted_id = hasilencrypt['ID']

                print("encrypted n1: ", encrypted_n1)
                print("id: ", encrypted_id)
            
            elif message == 'decrypt1':

                decrypted_n1 = decrypt_rsa(encrypted_n1, priv_key, nn)
                print('Decrypted message:', decrypted_n1)

                decrypted_id = decrypt_rsa(encrypted_id, priv_key, nn)
                print('Decrypted message:', decrypted_id)
            
            elif message == 'encrypt2':

                encryptclient_n1 = encrypt_rsa(decrypted_n1, client_e, client_n)
                encryptclient_n2 = encrypt_rsa(N2, client_e, client_n)
                print('encrypted N1 client: ', encryptclient_n1)
                print('encrypted N2 client: ', encryptclient_n2)

                encryptedmessage2 = json.dumps({'N1encrypt2': encryptclient_n1, 'N2encrypt2': encryptclient_n2})
                print(encryptedmessage2)

                client.send(encryptedmessage2.encode('utf-8'))

            elif message == 'encrypt3':
                time.sleep(2)
                encryptedmessaged3 = client.recv(1024).decode('utf-8')
                hasilencrypt3 = json.loads(encryptedmessaged3)
                print('Encrypted message: {}'.format(encryptedmessaged3))
                encrypt3_n2 = hasilencrypt3['N2']
                print("encrypted n2: ", encrypt3_n2)

            elif message == 'decrypt3':
                time.sleep(2)
                decrypted_message3 = decrypt_rsa(encrypt3_n2, priv_key, nn)
                print('Decrypted message:', decrypted_message3)
            
            elif message == 'encrypt4':
                encryptedn1 = encrypt_rsa(decrypted_n1, client_e, client_n)
                print('encrypted N1 client: ', encryptedn1)

                session_key = generate_random_hex()
                print("session key sblm di encrypt: ", session_key)

                session_key_array = [char for char in session_key]
                encrypted_session_key_array = encrypt_each_character(session_key_array, client_e, client_n)
                encryptedmessage4 = json.dumps({'N1encrypt4': encryptedn1, 'sessionkey': encrypted_session_key_array})
                print(encryptedmessage4)

                client.send(encryptedmessage4.encode('utf-8'))

            else:
                parts = message.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    cipher_text = parts[0]
                    banyak_kalimat = int(parts[1])
                    print(message)

                    print("cipher text: ", cipher_text)

                    plaintext = decrypt_des(cipher_text, session_key, banyak_kalimat)
                    print("plain text: ", plaintext)

        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            alias = aliases[index]
            aliases.remove(alias)
            break

def receive():
    while True:
        print('Server is running and listening...')
        client, address = server.accept()
        print('Connection is established with {}'.format(str(address)))

        alias = client.recv(1024).decode('utf-8')

        aliases.append(alias)
        clients.append(client)

        print('The alias of this client is {}'.format(alias))

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == "__main__":
    receive()