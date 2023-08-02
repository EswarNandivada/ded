from flask import Flask, render_template, request, redirect,session
import os
import random
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
import base64

class Encryptor:
    def key_create(self):
        key = Fernet.generate_key()
        return key

    def key_write(self, key, key_name):
        with open(key_name, 'wb') as mykey:
            mykey.write(key)

    def key_load(self, key_name):
        with open(key_name, 'rb') as mykey:
            key = mykey.read()
        return key

    def file_encrypt(self, key, original_file, encrypted_file):
        f = Fernet(key)
        with open(original_file, 'rb') as file:
            original = file.read()
        encrypted = f.encrypt(original)
        with open(encrypted_file, 'wb') as file:
            file.write(encrypted)

    def file_decrypt(self, key, encrypted_file, decrypted_file):
        f = Fernet(key)
        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()
        decrypted = f.decrypt(encrypted)
        with open(decrypted_file, 'wb') as file:
            file.write(decrypted)



class Eazypay:
    def __init__(self, encryption_key):
        self.merchant_id = '600541'
        self.encryption_key = encryption_key
        self.sub_merchant_id = '45'
        self.paymode = '9'
        self.return_url = ' https://doctorsolympiad.com/purchase-summary/order-received/'

    def get_payment_url(self, reference_no, amount,name,email, phone,optional_field=None):
        mandatory_field = self.get_mandatory_field(reference_no, amount,name,email,phone)
        optional_field = self.get_optional_field(optional_field)
        amount = self.get_encrypted_value(str(amount))
        reference_no = self.get_encrypted_value(str(reference_no))
        name = self.get_encrypted_value(name)
        email = self.get_encrypted_value(email)
        phone = self.get_encrypted_value(str(phone))

        payment_url = self.generate_payment_url(mandatory_field, optional_field, reference_no, amount)
        print(payment_urls)
        return payment_url

    def generate_payment_url(self, mandatory_field, optional_field, reference_no, amount):
        print(self.decrypt_data(mandatory_field.decode('utf-8')))
        encrypted_url = (
            f"https://eazypay.icicibank.com/EazyPG?merchantid={self.merchant_id}"
            f"&mandatory fields={mandatory_field.decode('utf-8')}&optional fields={optional_field}"
            f"&returnurl={self.get_return_url().decode('utf-8')}&Reference No={reference_no.decode('utf-8')}"
            f"&submerchantid={self.get_sub_merchant_id().decode('utf-8')}&transaction amount={amount.decode('utf-8')}"
            f"&paymode={self.get_paymode().decode('utf-8')}"
        )
        return encrypted_url

    def get_mandatory_field(self, reference_no, amount,name,email,phone):
        data = f'{reference_no}|{self.sub_merchant_id}|{amount}|{name}|{email}|{phone}'
        return self.get_encrypted_value(data)

    def get_optional_field(self, optional_field=None):
        if optional_field is not None:
            return self.get_encrypted_value(optional_field)
        return None


    def get_encrypted_value(self, data):
            f = Fernet(self.encryption_key)
            data = data.encode('utf-8')
            encrypted_data = f.encrypt(data)
            return encrypted_data

    def decrypt_data(self, encrypted_data):
        f = Fernet(self.encryption_key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')

    def get_return_url(self):
        return self.get_encrypted_value(self.return_url)

    def get_sub_merchant_id(self):
        return self.get_encrypted_value(self.sub_merchant_id)

    def get_paymode(self):
        return self.get_encrypted_value(self.paymode)

def generate_encryption_key():
    encryptor = Encryptor()
    # Convert the 16-byte key to a 32-byte key and base64-encode it
    key_128_bit = b'6000012605405020'
    encryption_key_256_bit = base64.urlsafe_b64encode(key_128_bit.ljust(32, b'\x00'))

    # Save the encryption key to the file 'mykey.key'
    encryptor.key_write(encryption_key_256_bit, 'mykey.key')

    return encryption_key_256_bit




def load_encryption_key():
    # Load the encryption key from the file 'mykey.key'
    encryptor = Encryptor()
    encryption_key = encryptor.key_load('mykey.key')
    return encryption_key



app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_emailid'
app.config['MAIL_PASSWORD'] = 'your_password'

mail = Mail(app)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/checkout/order-pay')
def payment():
    return render_template('payment_form.html')

def validate_form(amount):
    if amount < 0:
        return False
    return True


@app.route('/checkout/order-pay', methods=['POST'])
def process_payment():
    session['payer_name'] = request.form['payername']
    session['payer_phone'] = request.form['payerphone']
    session['payer_email'] = request.form['payeremail']
    amount = int(request.form['payeramount'])
    name = session['payer_name']
    email = session['payer_email']
    phone = session['payer_phone']

    if not validate_form(amount):
        return "Amount should be greater than Rs.10"

    # Check if the encryption key file exists
    if not os.path.exists('mykey.key'):
        # If the key file doesn't exist, generate and save the encryption key
        encryption_key = generate_encryption_key()
    else:
        # If the key file exists, load the encryption key from the file
        encryption_key = load_encryption_key()

    # Create an instance of Eazypay with the encryption key
    eazypay_integration = Eazypay(encryption_key)

    # reference_no = 8001  # You can use a random number generator if you prefer
    reference_no = str(random.randint(100000, 999999))

    payment_url = eazypay_integration.get_payment_url(reference_no, amount,name,email, phone)
    print(payment_url)
    
    return redirect(payment_url)



if __name__ == '__main__':
    app.run(debug=True)
