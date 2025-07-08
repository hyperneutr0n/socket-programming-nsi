import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad

def main():
    # --- Input Konfigurasi Server ---
    server_host = input("Masukkan IP Server (misal: 127.0.0.1): ")
    server_port = int(input("Masukkan Port Server (misal: 65432): "))

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"\n[*] Menghubungkan ke server di {server_host}:{server_port}...")
            s.connect((server_host, server_port))
            print("[+] Berhasil terhubung ke server.")

            # --- Proses Key Exchange (dilakukan sekali di luar loop) ---
            client_key = RSA.generate(2048)
            private_key = client_key
            public_key = client_key.publickey()
            print("[*] Pasangan kunci RSA client telah dibuat.")

            s.sendall(public_key.export_key())
            print("[*] Mengirim kunci publik RSA ke server.")

            encrypted_session_key = s.recv(256)

            rsa_cipher = PKCS1_OAEP.new(private_key)
            session_key = rsa_cipher.decrypt(encrypted_session_key)
            print("[+] Kunci Sesi AES berhasil didekripsi! Siap mengirim data.")
            # --- Key Exchange Selesai ---

            # --- Loop untuk mengirim data berulang kali ---
            while True:
                print("\n========================================")
                print("Silakan masukkan detail slip gaji (ketik 'exit' pada nama untuk keluar):")
                nama = input("Nama         : ")
                
                if nama.lower() == 'exit':
                    break

                jabatan = input("Jabatan      : ")
                gaji_pokok = input("Gaji Pokok   : ")
                lembur = input("Lembur       : ")
                total = input("Total        : ")
                
                slip_gaji = (
                    f"Nama: {nama}\n"
                    f"Jabatan: {jabatan}\n"
                    f"Gaji Pokok: {gaji_pokok}\n"
                    f"Lembur: {lembur}\n"
                    f"Total: {total}"
                )
                print("\n[*] Data slip gaji yang akan dikirim:\n---")
                print(slip_gaji)
                print("---\n")
                
                # --- Enkripsi dan Hashing ---
                # 1. Enkripsi data menggunakan AES mode CBC
                aes_cipher = AES.new(session_key, AES.MODE_CBC)
                data_bytes = slip_gaji.encode('utf-8')
                # Tambahkan padding agar data kelipatan 16 byte
                padded_data = pad(data_bytes, AES.block_size)
                ciphertext = aes_cipher.encrypt(padded_data)
                
                # 2. Buat hash MD5 dari data yang SUDAH dienkripsi
                md5_hash = hashlib.md5(ciphertext).hexdigest().encode('utf-8')

                # 3. Ambil IV (Initialization Vector) yang dibuat otomatis
                iv = aes_cipher.iv

                # Format Paket: [32 byte MD5 hash][16 byte IV][ciphertext]
                paket_untuk_dikirim = md5_hash + iv + ciphertext

                s.sendall(paket_untuk_dikirim)
                print("[*] Paket data terenkripsi terkirim.")

                response = s.recv(1024)
                print(f"[+] Respons Server: {response.decode('utf-8')}")

    except ConnectionRefusedError:
        print(f"[!] Koneksi ditolak. Pastikan server di {server_host}:{server_port} sudah berjalan.")
    except Exception as e:
        print(f"[!] Terjadi error: {e}")
    finally:
        print("[-] Program client selesai.")


if __name__ == "__main__":
    main()
