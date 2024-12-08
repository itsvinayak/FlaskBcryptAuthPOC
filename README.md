# FlaskBcryptAuthPOC

A Flask-based application that demonstrates secure user authentication using a custom bcrypt-inspired password hashing algorithm. This project includes user registration and login functionality, making it an excellent starting point for understanding secure password management in Python.


# The Bcrypt Algorithm for Secure Password Hashing

![alt text](https://cdn.hashnode.com/res/hashnode/image/upload/v1733676666017/419a708a-fc72-47b1-96e2-b6a211479dc2.png?w%3D1600%26h%3D840%26fit%3Dcrop%26crop%3Dentropy%26auto%3Dcompress%2Cformat%26format%3Dwebp)


Hashing is a cryptographic function that cannot be reversed. It takes an input of random size to produce fixed-size values. These fixed-size values are called hash values, and the cryptographic function is called the hashing function. Hashing has a consistent and predictable nature, meaning the same input will always produce the same hash value. It also exhibits the avalanche effect, which means even a slight change in the input results in a drastically different hash value, ensuring high security and uncertainty.

Hashing often employs salted hashing, where a unique random string called salt is added to the input before hashing, making each hash unique even for identical inputs

Salted hashing is primarily used in password hashing. One such algorithm is the bcrypt algorithm.

## **Bcrypt Algorithm**

The Bcrypt algorithm is based on the **Blowfish encryption algorithm.** bcrypt generates a unique **salt** (random string) for each password, and then the salt is combined with the password before hashing. This makes Bcrypt resistant to brute-force attacks.

### **How Bcrypt Works**

1. **Generating Salt:**
Bcrypt generates a random salt that is 16 bytes long and typically in Base64 format.

2. **Hashing the given string:**
The salt is combined with the password, and the resulting string is passed through the Blowfish encryption algorithm. bcrypt applies multiple rounds of hashing defined by the work factor. The high number of rounds makes it computationally expensive, which enhances its resistance to brute-force attacks.
The work factor, also known as cost, is defined by the logarithmic value of 2. If the cost is 12, this means 2^12 rounds. The higher the cost factor, the more time it takes to generate a hash, which in turn makes it harder for attackers to brute-force passwords.

3. **Format and Length of Bcrypt Hash:**
```bash
 $2y$12$odwBFokG9vTK/BAaRXKKl.9Q8KHXHeYSqpLi/gSNpmzSwQcaJb.gS
```

The given string consists of:

- `$2y$`: bcrypt version
- `12` is the cost factor (`2^12` rounds)
- The next **22 characters** (odwBFokG9vTK/BAaRXKKl.) are Base64-encoded salt
- The remaining characters are the Base64-encoded hash of the password and salt.

## **Python** Implementation **of Bcrypt Algorithm**

### Required Dependencies

```python
import hashlib
import os
import base64
```

### Class Initialization

```python
class Bcrypt:
    def __init__(self, rounds=12, salt_length=22):
        self.rounds = rounds
        self.salt_length = salt_length
```

- `Bcrypt` class encapsulates the functionality to hash and verify passwords

- **Parameters:**

### Generating a Salt

```python
def generate_salt(self, salt_length=None):
        if salt_length is None:
            salt_length = self.salt_length
        return base64.b64encode(os.urandom(salt_length)).decode('utf-8')[:salt_length]
```

Function **generate_salt** creates a random salt, which will be a unique value that will be added to passwords to ensure that even identical passwords produce different hashes.

### Hashing a Password

```python
def bcrypt_hash(self, password, salt, cost):
    password_salt = f'{password}{salt}'
    password_salt = password_salt.encode('utf-8')
    hashed_password_salt = hashlib.sha256(password_salt).hexdigest()
    for _ in range(2**cost):
        hashed_password_salt = hashlib.sha256(hashed_password_salt.encode('utf-8')).hexdigest()
    return hashed_password_salt

def hash_password(self, password, salt_length=None, cost=None):
    if salt_length is None:
        salt_length = self.salt_length
    if cost is None:
        cost = self.rounds
    salt = self.generate_salt(salt_length)
    hashed_password = self.bcrypt_hash(password, salt, cost)
    return f'{cost}${salt}${hashed_password}'
```

- Function **bcrypt_hash** securely hashes the password with the provided salt and cost factor.

- and Function **hash_password** generates a secure hash for the given password with a random salt.

# Code:

```python
import hashlib
import os
import base64



class Bcrypt:
    def __init__(self, rounds=12, salt_length=22):
        self.rounds = rounds
        self.salt_length = salt_length

    def generate_salt(self, salt_length=None):
        if salt_length is None:
            salt_length = self.salt_length
        return base64.b64encode(os.urandom(salt_length)).decode('utf-8')[:salt_length]

    def bcrypt_hash(self, password, salt, cost):
        password_salt = f'{password}{salt}'
        password_salt = password_salt.encode('utf-8')
        hashed_password_salt = hashlib.sha256(password_salt).hexdigest()
        for _ in range(2**cost):
            hashed_password_salt = hashlib.sha256(hashed_password_salt.encode('utf-8')).hexdigest()
        return hashed_password_salt

    def hash_password(self, password, salt_length=None, cost=None):
        if salt_length is None:
            salt_length = self.salt_length
        if cost is None:
            cost = self.rounds
        salt = self.generate_salt(salt_length)
        hashed_password = self.bcrypt_hash(password, salt, cost)
        return f'{cost}${salt}${hashed_password}'

    def verify_password(self, password, hashed_password):
        cost, salt, hashed_password = hashed_password.split('$')
        cost = int(cost)
        return hashed_password == self.bcrypt_hash(password, salt, cost)



bcrypt = Bcrypt()
password = 'vinayak'
hashed_password = bcrypt.hash_password(password)
print('string :', password, ' bcrypt hash :', hashed_password)
print('verify password :', bcrypt.verify_password(password, hashed_password))
print('verify invalid password :', bcrypt.verify_password('vinayak1', hashed_password))
```

## Output:

```txt
python test.py
string : vinayak  bcrypt hash : 12$FxJAsfQ2+7WuMj+ZGPAdFE$546a20a2ad890186ab661cb4969e8651a6f75eb5d4ffa0706ba4153414b65ea5
verify password : True
verify invalid password : False
```


# FLASK APP

## API Endpoints
- User Registration
    URL: http://127.0.0.1:5000/register
    Method: POST

    Request Body:
    ```json
    {
        "username": "vinayak",
        "password": "vinayak"
    }
    ```
    
    Response (Success):
    ```json
    {
        "message": "User registered successfully"
    }
    ```

    Response (Error - User already exists):
    ```json
    {
        "error": "User already exists"
    }
    ```
- User Login

    URL: http://127.0.0.1:5000/login
    Method: POST
    Request Body:
    ```json
    {
        "username": "vinayak",
        "password": "vinayak"
    }
    ```
    Response (Success):

    ```json
    {
        "message": "Login successful"
    }
    ```

    Response (Error - Invalid credentials):
    ```json
    {
        "error": "Invalid username or password"
    }
    ```





