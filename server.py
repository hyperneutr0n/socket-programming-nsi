import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

# --- Konfigurasi Server ---
HOST = '0.0.0.0'
PORT = 65432

def handle_connection(conn, addr):
    """Fungsi untuk menangani seluruh sesi koneksi dengan satu client."""
    print(f"\n[+] Koneksi baru dari {addr}")
    try:
        # --- Proses Key Exchange (dilakukan sekali per koneksi) ---
        client_public_key_data = conn.recv(1024)
        client_public_key = RSA.import_key(client_public_key_data)
        print(f"[*] Menerima kunci publik RSA dari {addr}.")

        session_key = get_random_bytes(32)
        print(f"[*] Membuat kunci sesi AES untuk {addr}.")

        rsa_cipher = PKCS1_OAEP.new(client_public_key)
        encrypted_session_key = rsa_cipher.encrypt(session_key)
        
        conn.sendall(encrypted_session_key)
        print(f"[*] Mengirim kunci sesi terenkripsi ke {addr}.")
        # --- Key Exchange Selesai ---

        # --- Loop untuk menerima data dari client ---
        while True:
            data_paket = conn.recv(2048)
            if not data_paket:
                print(f"[-] Client {addr} menutup koneksi.")
                break

            # --- Verifikasi dan Dekripsi ---
            try:
                # 1. Pisahkan paket: [32 byte MD5 hash][16 byte IV][ciphertext]
                received_hash = data_paket[:32]
                iv = data_paket[32:48]
                ciphertext = data_paket[48:]

                # 2. Hitung hash dari ciphertext yang diterima
                calculated_hash = hashlib.md5(ciphertext).hexdigest().encode('utf-8')

                # 3. Verifikasi integritas data dengan membandingkan hash
                if received_hash != calculated_hash:
                    print(f"[!] HASH TIDAK COCOK dari {addr}. Data mungkin korup!")
                    conn.sendall(b"ERROR: Hash tidak cocok. Pengiriman gagal.")
                    break # Putuskan koneksi jika integritas data diragukan

                print(f"[+] Hash dari {addr} terverifikasi.")

                # 4. Jika hash cocok, dekripsi data
                aes_cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
                # Lakukan dekripsi dan hapus padding
                decrypted_padded_data = aes_cipher.decrypt(ciphertext)
                decrypted_data = unpad(decrypted_padded_data, AES.block_size)
                
                print(f"[+] Pesan dari {addr}: {decrypted_data.decode('utf-8')}")
                conn.sendall(b"Pesan diterima dan terverifikasi.")

            except Exception as e:
                print(f"[!] Error saat memproses data dari {addr}: {e}")
                conn.sendall(b"ERROR: Gagal memproses data di server.")
                break

    except ConnectionResetError:
        print(f"[-] Koneksi dengan {addr} terputus secara paksa.")
    except Exception as e:
        print(f"[!] Terjadi error dengan {addr}: {e}")
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] Server (AES-CBC + MD5) mendengarkan di {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)

if __name__ == "__main__":
    main()
