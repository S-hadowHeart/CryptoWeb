from flask import Flask, render_template, request
import numpy as np
import requests
app = Flask(__name__)

def caesar_en(text, key):
    result = ''
    for char in text:
        if char.isalpha():
            shifted = ord(char) + key
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

def poly_en(text, key):
    result = ''
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            if char.islower():
                shift = ord(key[i % key_len].lower()) - ord('a')
                shifted = ord('a') + (ord(char) - ord('a') + shift) % 26
            elif char.isupper():
                shift = ord(key[i % key_len].upper()) - ord('A')
                shifted = ord('A') + (ord(char) - ord('A') + shift) % 26
            result += chr(shifted)
        else:
            result += char
    return result

def prepare_text(text):
    """Prepares the text by removing non-alphabetic characters and converting to uppercase."""
    text = ''.join(filter(str.isalpha, text.upper()))
    return text


def playfair_cipher(plaintext, key, mode):
    alphabet = 'abcdefghiklmnopqrstuvwxyz'
    key = key.lower().replace(' ', '').replace('j', 'i')
    key_square = ''.join(sorted(set(key + alphabet), key=lambda x: (key + alphabet).index(x)))
    plaintext = plaintext.lower().replace(' ', '').replace('j', 'i')
    plaintext += 'x' * (len(plaintext) % 2) 

    def process(digraph, encrypt):
        a, b = digraph
        indices = [key_square.index(char) for char in (a, b)]
        row_a, col_a = divmod(indices[0], 5)
        row_b, col_b = divmod(indices[1], 5)
        if row_a == row_b:
            col_a = (col_a + (1 if encrypt else -1)) % 5
            col_b = (col_b + (1 if encrypt else -1)) % 5
        elif col_a == col_b:
            row_a = (row_a + (1 if encrypt else -1)) % 5
            row_b = (row_b + (1 if encrypt else -1)) % 5
        else:
            col_a, col_b = col_b, col_a
        return key_square[row_a * 5 + col_a] + key_square[row_b * 5 + col_b]

    result = ''.join(process(plaintext[i:i + 2], mode == 'encrypt') for i in range(0, len(plaintext), 2))
    
    if mode == 'decrypt':
       
        result = result.rstrip('x')
    
    return result




def caesar_dn(text, key):
    result = ''
    for char in text:
        if char.isalpha():
            shifted = ord(char) - key
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

def poly_dn(text, key):
    result = ''
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            if char.islower():
                shift = ord(key[i % key_len].lower()) - ord('a')
                shifted = ord('a') + (ord(char) - ord('a') - shift) % 26
            elif char.isupper():
                shift = ord(key[i % key_len].upper()) - ord('A')
                shifted = ord('A') + (ord(char) - ord('A') - shift) % 26
            result += chr(shifted)
        else:
            result += char
    return result



def suggest_password(password):
   
    if len(password) < 8:
        return "Password should be at least 8 characters long."
    elif not any(char.isupper() for char in password):
        return "Password should contain at least one uppercase letter."
    elif not any(char.islower() for char in password):
        print("No lowercase letters found in password:", password)
        return "Password should contain at least one lowercase letter."

    elif not any(char.isdigit() for char in password):
        return "Password should contain at least one digit."
    elif not any(char in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for char in password):
        return "Password should contain at least one special character."
    else:
        return "Password is strong."

def getKeyMatrix(key):
    key_size = int(np.sqrt(len(key)))
    key_matrix = np.zeros((key_size, key_size), dtype=int)
    k = 0
    for i in range(key_size):
        for j in range(key_size):
            key_matrix[i][j] = (ord(key[k]) - 65) % 26
            k += 1
    return key_matrix

def modInverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return 1

def getInverseKeyMatrix(key_matrix):
    determinant = int(np.round(np.linalg.det(key_matrix)))
    adjoint_matrix = np.round(np.linalg.inv(key_matrix) * determinant)
    inverse_determinant = modInverse(determinant, 26)
    inverse_key_matrix = (adjoint_matrix * inverse_determinant) % 26
    return inverse_key_matrix

def encrypt(message_vector, key_matrix):
    return (key_matrix @ message_vector) % 26

def decrypt(cipher_vector, inverse_key_matrix):
    return (inverse_key_matrix @ cipher_vector) % 26

def hill_cipher(message, key, mode='encrypt'):
    key_matrix = getKeyMatrix(key)
    key_size = len(key_matrix)

    if len(message) % key_size != 0:
        message += 'X' * (key_size - len(message) % key_size)

    result_text = []
    for i in range(0, len(message), key_size):
        message_block = [ord(char) - 65 for char in message[i:i+key_size]]
        message_vector = np.array(message_block).reshape(-1, 1)

        if mode == 'encrypt':
            result_vector = encrypt(message_vector, key_matrix)
        elif mode == 'decrypt':
            inverse_key_matrix = getInverseKeyMatrix(key_matrix)
            result_vector = decrypt(message_vector, inverse_key_matrix)

        result_text.extend(int(char) for char in (result_vector % 26).flatten()) 

    if mode == 'encrypt':
        return ''.join(chr(char + 65) for char in result_text)
    elif mode == 'decrypt':
        return ''.join(chr(int(char) % 26 + 65) for char in result_text)
    
def hill_decrypt(cipher_text, key_matrix):
    inverse_key_matrix = getInverseKeyMatrix(key_matrix)
    key_size = len(key_matrix)

    plain_text = []
    for i in range(0, len(cipher_text), key_size):
        cipher_block = [ord(char) - 65 for char in cipher_text[i:i+key_size]]
        cipher_vector = np.array(cipher_block).reshape(-1, 1)
        decrypted_vector = (inverse_key_matrix @ cipher_vector) % 26
        plain_text.extend(decrypted_vector.flatten().astype(int)) 
    print(''.join(chr(char % 26 + 65) for char in plain_text))
    return ''.join(chr(char % 26 + 65) for char in plain_text)


def check_password_in_dictionary(password):

    last = ""
    response = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt")
    if response.status_code == 200:
        common_passwords = response.text.splitlines()
        if password in common_passwords:
            last= "Password is too common. Please choose a different one."
        else:
            last= suggest_password(password)
    else:
        last= "Unable to check password against common dictionary. Please try again later."
    return last



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/code', methods=['POST'])
def code():
    text = request.form['plain'].upper()
    key = request.form['key'].upper()
    passw = request.form['passw']
    method = request.form['method']
    button_clicked = request.form.get('enc') or request.form.get('dec') or request.form.get('')
    
    result = ""
    if button_clicked == 'enc':
        if method == "caesar":
            if key.isdigit():   
                result = caesar_en(text, int(key))
            else:
                result = "Invalid key. Please enter a valid integer."
        elif method == "polyalphabetic":
            result = poly_en(text, key)
        elif method == "playfair":
            result = playfair_cipher(text, key,"encrypt")
        elif method == "hill":
            result = hill_cipher(text, key)
    elif button_clicked == 'dec':
        if method == "caesar":
            if key.isdigit():  
                result = caesar_dn(text, int(key))
            else:
                result = "Invalid key. Please enter a valid integer."
        elif method == "polyalphabetic":
            result = poly_dn(text, key)
        elif method == "playfair":
            result = playfair_cipher(text, key,"decrypt")
        elif method == "hill":
            key_matrix = getKeyMatrix(key)
            result = hill_decrypt(text, key_matrix)
    else:
        result = check_password_in_dictionary(passw)

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
