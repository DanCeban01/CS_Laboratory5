### Course: Cryptography and Security
### Dan Ceban FAF-202

----

## Theory. Web Authentication & Authorisation.

Web authentication assumes the session-oriented client server model of the traditional web, where a user authenticates once when logging in with the application and sends subsequent messages within the same session. In contrast, the Internet Computer implements a model where each request is authenticated individually. In particular, there is no server that can generate a challenge to be signed by the security device, as there is no stateful session between the browser and the Internet Computer. Recall, however, that in the typical web authentication flow, the secure device provides a digital signature on the challenge sent by the server.

Authorization is a process by which a server determines if the client has permission to use a resource or access a file. Authorization is usually coupled with authentication so that the server has some concept of who the client is that is requesting access. The type of authentication required for authorization may vary; passwords may be required in some cases but not in others. In some cases, there is no authorization; any user may be use a resource or access a file simply by asking for it. Most of the web pages on the Internet require no authentication or authorization.

----

## Objectives:
1. Take what you have at the moment from previous laboratory works and put it in a web service / serveral web services.
2. Your services should have implemented basic authentication and MFA (the authentication factors of your choice).
3. Your web app needs to simulate user authorization and the way you authorise user is also a choice that needs to be done by you.
4. As services that your application could provide, you could use the classical ciphers. Basically the user would like to get access and use the classical ciphers, but they need to authenticate and be authorized. 

----

## Implementation
I have created a web service where you can register, log in using 2FA, and use the encryption/decryption services by sending requests to endpoints.The server runs on `http://127.0.0.1:5000`

### TOTP Authentication (2FA)

For authentication, TOTP is used.

One-time password (OTP) systems provide a mechanism for logging on to a network or service using a unique password that can only be used once, as the name suggests. TOTP stands for Time-based One-Time Passwords and is a common form of two factor authentication (2FA). Unique numeric passwords are generated with a standardized algorithm that uses the current time as an input. The time-based passwords are available offline and provide user friendly, increased account security when used as a second factor. When registering, the user has to provide an email and a password, then a link with the QR code will be sent back. It has to be scanned using Google Authenticator.

### register

Request is made:

```json
    {"email": "aut.user.try@gmail.com", "password": "Moscow01"}
```

Response is get:

```
Access the link to get the Qr Code. Scan it using Google Authenticator:
https://chart.googleapis.com/chart?cht=qr&chs=500x500&chl=otpauth://totp/Laboratory%20Work%20Nr.5:user1%40gmail.com?secret=MEEQ2R6V4S7HL5PDEO2SGWUTDCWZ4DBZ&issuer=Laboratory%20Work%20Nr.5
```

An OTP will be generated in the Google Authenticator app, and it will be used for logging in.

#### Register Endpoint

```python
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        register_data = {
            'email': data['email'],
            'password': data['password']
        }
        email = register_data['email']
        password = register_data['password']
        user_type = "user"
        secret_string = pyotp.random_base32()
        totp = pyotp.TOTP(secret_string)
        print("Creating user")
        create_user(email, password, user_type, secret_string)
        totp_uri = totp.provisioning_uri(name=email, issuer_name="Laboratory Work Nr.5")
        qr_uri = "https://chart.googleapis.com/chart?cht=qr&chs=500x500&chl=" + totp_uri
        return f'Access the link to get the Qr Code. Scan it using Google Authenticator: {qr_uri}'
    except Exception as e:
        print(str(e))
        return "Error occured! Email already in use or worng data sent"
```

With pyotp library, a secret string is assigned to the user. After that, TOTP is used and create a specific URL for the QR code.

When logging in, the user provides email, password, and the otp generated in Google Authenticator. The server checks if the data is correct, and sends a success message with a token that has to be used when sending requests to service endpoints.

### Login Endpoint

```python
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        login_data = {
            'email': data['email'],
            'password': data['password'],
            'otp': data['otp']
        }
        email = login_data['email']
        password = login_data['password']
        otp = login_data['otp']
        user = get_user(email)
        user_password = user[0][1]
        totp = user[0][3]
        totp = pyotp.TOTP(totp)
        if user_password != password:
            return "Incorrect password."
        if totp.now() != otp:
            return "Incorrect OTP code."
        alphabet = string.ascii_letters + string.punctuation
        if email not in tokens:
            token = ''.join(secrets.choice(alphabet) for i in range(8))
            tokens.update({email: token})
            return f'Login success! Use the token ({token}) to make requests.'
        token = tokens[email]
        print(tokens)
        return f'Already logged in! Use the token ({token}) to make requests.'
    except Exception as e:
        print(str(e))
        return "Something went wrong! Check if you introduced the correct data." 
```

The server checks if the email, password and otp are correct, then logs the user in, by adding in a in-memory database, in this case a dictionary, the email and a random token, which will be used when sending requests.

### Caesar Cipher Endpoint

```python
@app.route('/caesar', methods=['POST'])
def caesar():
    try:
        data = request.get_json()
        login_data = {
            'token': data['token'],
            'message': data['message'],
            'key': data['key']
        }
        token = login_data['token']
        user_message = login_data['message']
        user_key = login_data['key']
        if token not in tokens.values():
            return "Something went wrong! Check if you provided the correct token or if you are logged in."
        print("Caesar Cipher")
        caesarCipher = Caesar()
        message = user_message.upper()
        key = int(user_key)
        encrypted_message = caesarCipher.encrypt(message, key)
        decrypted_message = caesarCipher.decrypt(encrypted_message, key)
        return f'The original message: {message}, The encrypted message: {encrypted_message}, The decrypted message: ' \
               f'{decrypted_message}'
    except Exception as e:
        print(str(e))
        return "Error occurred!"
```

### Other endpoints from implemented ciphers:
### Vignere, Vernam and Playfair

```python
{"token": "Qr[*?Bdi", "message": "university", "key": "utm"}
```
----

### Authorization (RBAC)

Some services provided cannot been acces by the User profile because of security reasons, in order to get full access to all options is needed to have the Admin profile role. For example:

### Simple User 

Request

```python
{"token": "Qr[*?Bdi", "message": "university", "key": "utm"}
```

Response

```
You don't have enough access rights.
```

To get the admin role, an admin account has to be created. It can be done by accessing `/admin` endpoint and registering using `4#17QZksEGi2` password.

### Admin Profile

Request

```json
    {"email": "admin1@gmail.com", "password": "Washington01", "secret": "4#17QZksEGi2"}
```

Response

```
Access the link to get the Qr Code. Scan it using Google Authenticator:
https://chart.googleapis.com/chart?cht=qr&chs=500x500&chl=otpauth://totp/Laboratory%20Work%20Nr.5:admin%40gmail.com?secret=J7UWQBYLGII3A4A53VGSZN5QWAOUPKNR&issuer=Laboratory%20Work%20Nr.5
```

Request

```python
{"token": "#LRSxEJL", "message": "university", "key": "utm"}
```

Response

```
The original message: UNIVERSITY, The encrypted message: 11000101010000011100010100110100010011111001010000111000111001011011011111011010, The decrypted message: UNIVERSITY
```

### Other Accesible only by Admin Profile options:

### Asymmetric and Hashing

```
{"token": "#LRSxEJL", "message": "university"}
```

----

### Database

To perform operations in this laboratory work is needed to implement SQLite, and create the Users Table. See example below:

```python
def create_initial_db_resources():
    cur.execute(
        "CREATE TABLE IF NOT EXISTS Users(email varchar unique, password varchar, user_type varchar, totp varchar)")
    cur.execute("SELECT * FROM Users")
    print(cur.fetchall())
```

Here is how the user profile is created:

```python
def create_user(email, password, user_type, totp):
    cur.execute("INSERT INTO Users(email, password, user_type, totp) values(:email, :password, :user_type, :totp)", {
        'email': email,
        'password': password,
        'user_type': user_type,
        'totp': totp
    })
    print("Created user successfully")
    con.commit()
```

And here is how the user is get by the email:

```python
def get_user(email):
    try:
        cur.execute("SELECT email, password, user_type, totp FROM Users WHERE email = :email", {
            'email': email
        })
        print("User found successfully")
        return cur.fetchall()
    except Exception as e:
        print("Exception occurred while checking for the user")
        raise e
```

----

### Conclusion

Authentication and authorization are two vital information security processes that administrators use to protect systems and information. Authentication verifies the identity of a user or service, and authorization determines their access rights. Although the two terms sound alike, they play separate but equally essential roles in securing applications and data. Understanding the difference is crucial. Combined, they determine the security of a system. You cannot have a secure solution unless you have configured both authentication and authorization correctly.

Authorization is the security process that determines a user or service's level of access. In technology, we use authorization to give users or services permission to access some data or perform a particular action. It is vital to note the difference here between authentication and authorization. Authentication verifies the user before allowing them access, and authorization determines what they can do once the system has granted them access.

Implementing this two important for Informational Security technologies in my final laboratory work helped me to extend the understanding of how modern security works in web technologies. The purpose of authentication is to verify that someone or something is who or what they claim to be. There are many forms of authentication. For example, the art world has processes and institutions that confirm a painting or sculpture is the work of a particular artist. Likewise, governments use different authentication techniques to protect their currency from counterfeiting. Typically, authentication protects items of value, and in the information age, it protects systems and data.

Authentication and authorization are similar in that they are two parts of the underlying process that provides access. Consequently, the two terms are often confused in information security as they share the same "auth" abbreviation. Authentication and authorization are also similar in the way they both leverage identity. For example, one verifies an identity before granting access, while the other uses this verified identity to control access.

As a final word, through the whole course got the possibility to try my power in implementing different ciphers, technologies of encrypting, hashing function. The experience from this laboratory works will be usefull in my carrier as software engineer.