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

def decrypt_each_character(encrypted_array, d, n):
    decrypted_array = []

    for encrypted_char in encrypted_array:
        # Mendekripsi karakter
        decrypted_ascii = decrypt_rsa(encrypted_char, d, n)

        # Mengonversi nilai ASCII kembali menjadi karakter
        decrypted_char = chr(decrypted_ascii)

        # Menambahkan karakter ke array
        decrypted_array.append(decrypted_char)

    return decrypted_array

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

p = 521
q = 569

# Key generation
full_pub, full_priv, pub_key, priv_key, nn = rsa_key(p, q)

N1 = 123
ID = 13

server_n = None
server_e = None
n1_server = None
n2_server = None
decrypt_server_n2 = None
sessionkey = None
n1last = None

def client_receive(client):
    global server_n, server_e, n1_server, n2_server, decrypt_server_n2, n1last, sessionkey
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message.startswith('{"e":') or message.startswith('{"n":'):
                server_pub_key = json.loads(message)
                print('Received server public key:', server_pub_key)
                server_n = server_pub_key['n']
                server_e = server_pub_key['e']
                print('server n: ', server_n)
                print('server e: ', server_e)
            
            elif message.startswith('{"N1encrypt2":') or message.startswith('{"N2encrypt2":'):
                n1n2 = json.loads(message)
                print('Received N1 and N2 from server: ', n1n2)
                n1_server = n1n2['N1encrypt2']
                n2_server = n1n2['N2encrypt2']
                print('N1 dari server: ', n1_server)
                print('N2 dari server: ', n2_server)
            
            elif message.startswith('{"N1encrypt4":') or message.startswith('{"sessionkey":'):
                n1sessionkey = json.loads(message)
                print('Received N1 and sessionkey from server: ', n1sessionkey)

                n1last = n1sessionkey['N1encrypt4']
                sessionkey = n1sessionkey['sessionkey']

                print('N1 dari server: ', n1last)
                print('Session key: ', sessionkey)
            
            else:
                print(message)
        except Exception as e:
            print('Error:', e)
            break

def client_send(client, alias, full_pub):
    global server_n, server_e, n1_server, n2_server, decrypt_server_n2, n1last, sessionkey
    try:
        client.send(('ALIAS:' + alias).encode('utf-8'))
        
        while True:
            command = input("Enter 'share' to exchange public keys\n, 'encrypt1' to encrypt1\n, 'decrypt1' to decrypt1\n, 'encrypt2' to encrypt2\n, 'decrypt2' to decrypt2\n, 'encrypt3' to encrypt3\n, 'decrypt3' to decrypt3\n, 'encrypt4' to encrypt4\n, 'decrypt4' to decrypt4\n, 'message' to send message\n, or 'exit' to quit: ")
            client.send(command.encode('utf-8'))
            if command == 'exit':
                break

            if command == 'share':
                pub_key_json = json.dumps({'e': full_pub[0], 'n': full_pub[1]})
                client.send(pub_key_json.encode('utf-8'))
                time.sleep(2)

            elif command == 'encrypt1':
                if server_n is not None and server_e is not None:

                    encrypted_n1 = encrypt_rsa(N1, server_e, server_n)
                    encrypted_id = encrypt_rsa(ID, server_e, server_n)
                    print(encrypted_n1)
                    print(encrypted_id)
                    
                    encrypted_message = json.dumps({'N1': encrypted_n1, 'ID': encrypted_id})
                    print(encrypted_message)
                    client.send(encrypted_message.encode('utf-8'))
                    time.sleep(2)
                else:
                    print("Public key not received yet.")
            
            elif command == 'decrypt2':
                decrypt_server_n1 = decrypt_rsa(n1_server, priv_key, nn)
                decrypt_server_n2 = decrypt_rsa(n2_server, priv_key, nn)
                print("decrypt n1: ", decrypt_server_n1)
                print("decrypt n2: ", decrypt_server_n2)
            
            elif command == 'encrypt3':
                encrypt3_n2 = encrypt_rsa(decrypt_server_n2, server_e, server_n)
                print(encrypt3_n2)

                encrypted_message3 = json.dumps({'N2': encrypt3_n2})
                print(encrypted_message3)

                client.send(encrypted_message3.encode('utf-8'))
                time.sleep(2)
            
            elif command == 'decrypt4':
                decrypt_last_n1 = decrypt_rsa(n1last, priv_key, nn)
                decrypted_hex_session_key = decrypt_each_character(sessionkey, priv_key, nn)
                print("decrypt n1: ", decrypt_server_n1)
                print("decrypt session key: ", decrypted_hex_session_key)

                hasil_sessionkey = ''.join(decrypted_hex_session_key)
                print("session key sebenarnya: ", hasil_sessionkey)
            
            elif command == "message":
                while True:
                    pt = input("Input kalimat: ")
                    pt = pt.upper()
                    print(pt)
                    banyak_kalimat = len(pt)
                    try:
                        # Melakukan enkripsi dengan fungsi encrypt
                        cipher_text = encrypt_des(pt, hasil_sessionkey)

                        # Lakukan sesuatu dengan hasil enkripsi
                        print("Hasil Enkripsi:", cipher_text)

                    except Exception as e:
                        # Menangani error yang mungkin terjadi
                        print("Terjadi error saat melakukan enkripsi:", str(e))

                    message_with_data = '{} {}'.format(cipher_text, banyak_kalimat)
                    client.send(message_with_data.encode('utf-8'))
            time.sleep(2)
    except Exception as e:
        print('Error:', e)

if __name__ == "__main__":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((socket.gethostname(), 5000))
    alias = input('Choose an alias >>> ')

    receive_thread = threading.Thread(target=client_receive, args=(client,))
    receive_thread.start()

    send_thread = threading.Thread(target=client_send, args=(client, alias, full_pub))
    send_thread.start()

    receive_thread.join()
    send_thread.join()
    client.close()