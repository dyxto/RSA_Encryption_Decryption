import random
import math
from sympy import randprime, mod_inverse
import tkinter as tk


'''1. Generate Random Prime Numbers - Complete'''
# choose a random prime in range
p_value = randprime(100,500)
q_value = randprime(100,500)
n_value = p_value * q_value
m_value = (p_value-1)*(q_value-1)

print("")
print(f'p: {p_value}')
print(f'q: {q_value}')
print(f'n: {n_value}')
print(f'm: {m_value}')


'''2. Encryption (Public Key) - Complete'''
e_value = 0
e_value_list = []

def gcd(a, b):
    return math.gcd(a, b)

# find an e-value where gcd(e,n) == 1
# add the value to a list
for e in range(2, m_value):
    if gcd(e, m_value) == 1:
        e_value_list.append(e)
# choose one e-value from the list of compatible e-values
e_value = random.choice(e_value_list)
print(f'e (public key): {e_value}')


'''3. Decryption (Private Key) - Complete'''
d_value = mod_inverse(e_value, m_value)
print(f'd (private key): {d_value}')


'''4b. Encrypting'''
def encrypt(plaintext):
    # encoding string input into Unicode code point (& converting to integer)
    encodedMessage = int(ord(plaintext))
    # print(f'encoded letter: {encodedMessage}') # prints each encoded letter
    
    # ciphertext = (plaintext^e) mod n
    ciphertext = pow(encodedMessage,e_value) % n_value 
    return ciphertext


'''5a. Decrypting '''
def decrypt(ciphertext):
    # plaintext = (ciphertext^d) mod n
    plaintext = pow(int(ciphertext),d_value) % n_value
    plaintext = str(chr(plaintext))
    return plaintext


print(" ------ RUNNING THE GUI !!! ------")

# --- GUI Functions ---

def get_user_message():
    word = entry_plain.get()
    global letters
    letters = [char for char in word if char != ' ']
    result_plain.set(f"Plaintext (no spaces): {''.join(letters)}")

def encrypt_user_message():
    encrypted_message = [str(encrypt(char)) for char in letters]
    result_encrypted.set(' '.join(encrypted_message))

def decrypt_user_message():
    encrypted_input = entry_decrypt.get()
    try:
        decrypt_this = encrypted_input.strip().split()
        decrypted_message = ''.join([decrypt(val) for val in decrypt_this])
        result_decrypted.set(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        result_decrypted.set("Error in decryption. Check your input.")

def copy_text():
    window.clipboard_clear()
    window.clipboard_append(result_encrypted.get())

def paste_text():
    text = result_encrypted.get()
    entry_decrypt.delete(tk.END)
    entry_decrypt.insert(tk.END, text)

# --- GUI Layout ---

window = tk.Tk()
window.title("RSA Message GUI")
window.geometry("600x400")
window.resizable(True, True)

# --- Input Message Section ---

tk.Label(window, text="Step 1: Enter your message (plaintext)", font=("Arial", 12, 'bold')).pack(pady=5)
entry_plain = tk.Entry(window, width=50)
entry_plain.pack()

tk.Button(window, text="Process Message", command=get_user_message).pack(pady=5)
result_plain = tk.StringVar()
tk.Label(window, textvariable=result_plain, fg="green").pack()

# --- Encryption Section ---

tk.Label(window, text="Step 2: Encrypt Message", font=("Arial", 12, 'bold')).pack(pady=5)
tk.Button(window, text="Encrypt", command=encrypt_user_message).pack(pady=5)
result_encrypted = tk.StringVar()
tk.Label(window, textvariable=result_encrypted, fg="red", wraplength=500).pack()

copy_button = tk.Button(window, text="Copy", command=copy_text)
copy_button.pack()

# --- Decryption Section ---

tk.Label(window, text="Step 3: Decrypt Encrypted Message", font=("Arial", 12, 'bold')).pack(pady=5)
entry_decrypt = tk.Entry(window, width=60)
entry_decrypt.pack()

copy_button = tk.Button(window, text="Paste", command=paste_text)
copy_button.pack()

tk.Button(window, text="Decrypt", command=decrypt_user_message).pack(pady=5)
result_decrypted = tk.StringVar()
tk.Label(window, textvariable=result_decrypted, fg="magenta", wraplength=500).pack()

# --- Run App ---

if __name__ == "__main__":
    window.mainloop()
