from flask import Flask, request, redirect, render_template, url_for, flash,session,abort,jsonify
import flask_excel as excel
from flask_session import Session
import mysql.connector
import random
from io import BytesIO
from key import secret_key, salt, salt2
from itsdangerous import URLSafeTimedSerializer
from stoken import token
from cmail import sendmail
import os
import uuid
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
import stripe
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import hashlib

app = Flask(__name__)
app.secret_key = secret_key
app.config['SESSION_TYPE'] = 'filesystem'
excel.init_excel(app)
Session(app)

#mydb = mysql.connector.connect(host='localhost', user='root', password='Eswar@2001', db='doctors',pool_name='DED',pool_size=30)
db= os.environ['RDS_DB_NAME']
user=os.environ['RDS_USERNAME']
password=os.environ['RDS_PASSWORD']
host=os.environ['RDS_HOSTNAME']
port=os.environ['RDS_PORT']
with mysql.connector.connect(host=host,user=user,password=password,db=db) as conn:
     cursor=conn.cursor(buffered=True)
     # cursor.execute("DROP TABLE games")
     cursor.execute("CREATE TABLE if not exists register (ID int NOT NULL AUTO_INCREMENT,FirstName varchar(25) DEFAULT NULL,LastName varchar(25) DEFAULT NULL,Email varchar(50) DEFAULT NULL,PASSWORD longblob,mobileno bigint DEFAULT NULL,age int DEFAULT NULL,gender varchar(10) DEFAULT NULL,DOB date DEFAULT NULL,city text,address text,state text,country text,degree varchar(10) DEFAULT NULL,MCI_ID varchar(20) DEFAULT NULL,member varchar(20) DEFAULT NULL,SHIRT_SIZE enum('S','M','L','XL','XXL','XXXL','XXXXL') DEFAULT NULL,acception varchar(30) DEFAULT 'No',status varchar(20) NOT NULL DEFAULT 'pending',PRIMARY KEY (ID),UNIQUE KEY Email (Email),UNIQUE KEY mobileno (mobileno))")
     cursor.execute("CREATE TABLE if not exists game (ID INT, game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),AMOUNT INT UNSIGNED)")
     cursor.execute("create table if not exists games(game_name varchar(30),amount int unsigned,team_count int)")
     # cursor.execute("insert into games values('ATHLETICS',1500,1),('ARCHERY',30,1),('BADMINTON',1500,2),('BASKETBALL',10000,9),('BALL BADMINTON',10000,7),('CARROMS',1500,2),('CHESS',30,1),('CYCLOTHON',30,1),('JUMPS',1500,1),('SWIMMING',1500,1),('THROW',1500,1),('ROWING',1500,1),('SHOOTING',1500,1),('ROLLER SKATING',1500,1),('FENCING',1500,1),('TENNIKOIT',1500,1),('TABLE TENNIS',1500,2),('LAWN TENNIS',1500,2),('CRICKET WHITE BALL',30000,14),('HARD TENNIS CRICKET',20000,14),('WOMEN BOX CRICKET',10000,7),('VOLLEY BALL',10000,9),('FOOTBALL',10000,11),('KHO KHO',10000,12),('KABADDI',10000,10),('THROWBALL',10000,10),('TUG OF WAR',5000,10)")
     cursor.execute("create table if not exists payments(ordid varchar(36),id int,game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),amount int unsigned,date timestamp default now() on update now(),foreign key(id) references register(id))")
     cursor.execute("CREATE TABLE if not exists sub_games (game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),id int ,category varchar(50),team_number int unique, date timestamp default current_timestamp on update current_timestamp,foreign key(id) references register(id))")
     cursor.execute("create table if not exists teams(teamid int,id int,status enum('Accept','Pending'),foreign key(teamid) references sub_games(team_number),foreign key(id) references register(id))")
     # cursor.execute("alter table payments modify ordid int unsigned")
     # cursor.execute("alter table payments modify amount decimal(8,3)")
     cursor.close()
mydb=mysql.connector.connect(host=host,user=user,password=password,db=db,pool_name='DED',pool_size=30)

stripe.api_key='sk_test_51NTKipSDmVNK7hRpj4DLpymMTojbp0sntuHknEF9Kv3cGY79VkNbmBcfxDmTLXa9UIGKiiqp8drQQhzsjoia58Sm00Kuzg9vYt'

# Configure the upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/certificates')
app.config['UPLOAD_FOLDERS'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/photos')
app.config['UPLOAD_FOLDERSS'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/dob')


bcrypt = Bcrypt(app)

class Eazypay:
    def __init__(self,eid,game,ref):
        self.merchant_id = '376890'
        self.encryption_key = b'3777003168901000'
        self.sub_merchant_id = '20'
        self.paymode = '9'
        self.ref=ref
        self.eid=eid
        self.game=game
        self.return_url = f'https://doctorsolympiad.com/purchase-summary/order-received/{eid}/{game}/{ref}'

    def get_payment_url(self, reference_no, amount,name,email, phone,optional_field=None):
        mandatory_field = self.get_mandatory_field(reference_no, amount,name,email,phone)
        optional_field = self.get_optional_field(optional_field)
        amount = self.get_encrypted_value(str(amount))
        reference_no = self.get_encrypted_value(str(reference_no))
        name = self.get_encrypted_value(name)
        email = self.get_encrypted_value(email)
        phone = self.get_encrypted_value(str(phone))

        payment_url = self.generate_payment_url(mandatory_field, optional_field, reference_no, amount)
        
        return payment_url

    def generate_payment_url(self, mandatory_field, optional_field, reference_no, amount):
        
        encrypted_url = (
            f"https://eazypay.icicibank.com/EazyPG?merchantid={self.merchant_id}"
            f"&mandatory fields={mandatory_field}&optional fields={optional_field}"
            f"&returnurl={self.get_return_url()}&Reference No={reference_no}"
            f"&submerchantid={self.get_sub_merchant_id()}&transaction amount={amount}"
            f"&paymode={self.get_paymode()}"
        )
        return encrypted_url

    def get_mandatory_field(self, reference_no, amount,name,email,phone):
        data = f'{reference_no}|{self.sub_merchant_id}|{amount}|{name}|{email}|{phone}'
        return self.get_encrypted_value(data)

    def get_optional_field(self, optional_field=None):
        if optional_field is not None:
            return self.get_encrypted_value(optional_field)
        return ''


    def get_encrypted_value(self, data):
        cipher = AES.new(self.encryption_key, AES.MODE_ECB)
        padded_plaintext = pad(data.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        encrypted_base64 = base64.b64encode(ciphertext)
        return encrypted_base64.decode('utf-8')

    def decrypt(self, encrypted_data):
        cipher = AES.new(self.encryption_key, AES.MODE_ECB)
        encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        decrypted_data = cipher.decrypt(encrypted_data_bytes)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return unpadded_data.decode('utf-8')


    def get_return_url(self):
        return self.get_encrypted_value(self.return_url)

    def get_sub_merchant_id(self):
        return self.get_encrypted_value(self.sub_merchant_id)

    def get_paymode(self):
        return self.get_encrypted_value(self.paymode)

def payment_success_exec():
    print(request.form)
    
    if request.method == 'POST' and 'Total Amount' in request.form and request.form['Response Code'] == 'E000':
        res = request.form
        
        # Same encryption key that we gave for generating the URL
        aes_key_for_payment_success = b'3777003168901000'  # Replace this with the actual key

        data = {
            'Response_Code': res['Response Code'],
            'Unique_Ref_Number': res['Unique Ref Number'],
            'Service_Tax_Amount': res['Service Tax Amount'],
            'Processing_Fee_Amount': res['Processing Fee Amount'],
            'Total_Amount': res['Total Amount'],
            'Transaction_Amount': res['Transaction Amount'],
            'Transaction_Date': res['Transaction Date'],
            'Interchange_Value': res['Interchange Value'],
            'TDR': res['TDR'],
            'Payment_Mode': res['Payment Mode'],
            'SubMerchantId': res['SubMerchantId'],
            'ReferenceNo': res['ReferenceNo'],
            'ID': res['ID'],
            'RS': res['RS'],
            'TPS': res['TPS'],
        }
        print(data)

        verification_key = f"{data['ID']}|{data['Response_Code']}|{data['Unique_Ref_Number']}|" \
                           f"{data['Service_Tax_Amount']}|{data['Processing_Fee_Amount']}|" \
                           f"{data['Total_Amount']}|{data['Transaction_Amount']}|" \
                           f"{data['Transaction_Date']}|{data['Interchange_Value']}|" \
                           f"{data['TDR']}|{data['Payment_Mode']}|{data['SubMerchantId']}|" \
                           f"{data['ReferenceNo']}|{data['TPS']}|{aes_key_for_payment_success}"
        
        print(verification_key)
        encrypted_message = hashlib.sha512(verification_key.encode()).hexdigest()
        print(encrypted_message)
        if encrypted_message == data['RS']:
            return True
        else:
            return False
    else:
        return False




def get_response_message(code):
    rc = {
        'E000': 'Payment Successful.',
        'E001': 'Unauthorized Payment Mode',
        'E002': 'Unauthorized Key',
        'E003' :'Unauthorized Packet', 
        'E004' :'Unauthorized Merchant', 
        'E005' :'Unauthorized Return URL', 
        'E006' :'"Transaction Already Paid, Received Confirmation from the Bank, Yet to Settle the transaction with the Bank', 
        'E007' :'Transaction Failed', 
        'E008' :'Failure from Third Party due to Technical Error', 
        'E009' :'Bill Already Expired', 
        'E0031' :'Mandatory fields coming from merchant are empty', 
        'E0032' :'Mandatory fields coming from database are empty', 
        'E0033' :'Payment mode coming from merchant is empty', 
        'E0034' :'PG Reference number coming from merchant is empty', 
        'E0035' :'Sub merchant id coming from merchant is empty', 
        'E0036' :'Transaction amount coming from merchant is empty', 
        'E0037' :'Payment mode coming from merchant is other than 0 to 9', 
        'E0038' :'Transaction amount coming from merchant is more than 9 digit length', 
        'E0039' :'Mandatory value Email in wrong format', 
        'E00310' :'Mandatory value mobile number in wrong format', 
        'E00311' :'Mandatory value amount in wrong format', 
        'E00312' :'Mandatory value Pan card in wrong format', 
        'E00313' :'Mandatory value Date in wrong format', 
        'E00314' :'Mandatory value String in wrong format', 
        'E00315' :'Optional value Email in wrong format', 
        'E00316' :'Optional value mobile number in wrong format', 
        'E00317' :'Optional value amount in wrong format', 
        'E00318' :'Optional value pan card number in wrong format', 
        'E00319' :'Optional value date in wrong format', 
        'E00320' :'Optional value string in wrong format', 
        'E00321' :'Request packet mandatory columns is not equal to mandatory columns set in enrolment or optional columns are not equal to optional columns length set in enrolment', 
        'E00322' :'Reference Number Blank', 
        'E00323' :'Mandatory Columns are Blank', 
        'E00324' :'Merchant Reference Number and Mandatory Columns are Blank', 
        'E00325' :'Merchant Reference Number Duplicate', 
        'E00326' :'Sub merchant id coming from merchant is non numeric', 
        'E00327' :'Cash Challan Generated', 
        'E00328' :'Cheque Challan Generated', 
        'E00329' :'NEFT Challan Generated', 
        'E00330' :'Transaction Amount and Mandatory Transaction Amount mismatch in Request URL', 
        'E00331' :'UPI Transaction Initiated Please Accept or Reject the Transaction', 
        'E00332' :'Challan Already Generated, Please re-initiate with unique reference number', 
        'E00333' :'Referer value is null / invalid Referer', 
        'E00334' :'Value of Mandatory parameter Reference No and Request Reference No are not matched', 
        'E00335' :'Payment has been cancelled',
        'E0801' :'FAIL', 
        'E0802' :'User Dropped', 
        'E0803' :'Canceled by user', 
        'E0804' :'User Request arrived but card brand not supported', 
        'E0805' :'Checkout page rendered Card function not supported', 
        'E0806' :'Forwarded / Exceeds withdrawal amount limit', 
        'E0807' :'PG Fwd Fail / Issuer Authentication Server failure', 
        'E0808' :'Session expiry / Failed Initiate Check, Card BIN not present', 
        'E0809' :'Reversed / Expired Card', 
        'E0810' :'Unable to Authorize', 
        'E0811' :'Invalid Response Code or Guide received from Issuer', 
        'E0812' :'Do not honor', 
        'E0813' :'Invalid transaction', 
        'E0814' :'Not Matched with the entered amount', 
        'E0815' :'Not sufficient funds', 
        'E0816' :'No Match with the card number', 
        'E0817' :'General Error', 
        'E0818' :'Suspected fraud', 
        'E0819' :'User Inactive', 
        'E0820' :'ECI 1 and ECI6 Error for Debit Cards and Credit Cards', 
        'E0821' :'ECI 7 for Debit Cards and Credit Cards', 
        'E0822' :'System error. Could not process transaction', 
        'E0823' :'Invalid 3D Secure values', 
        'E0824' :'Bad Track Data', 
        'E0825' :'Transaction not permitted to cardholder', 
        'E0826' :'Rupay timeout from issuing bank', 
        'E0827' :'OCEAN for Debit Cards and Credit Cards', 
        'E0828' :'E-commerce decline', 
        'E0829' :'This transaction is already in process or already processed', 
        'E0830' :'Issuer or switch is inoperative', 
        'E0831' :'Exceeds withdrawal frequency limit', 
        'E0832' :'Restricted card', 
        'E0833' :'Lost card', 
        'E0834' :'Communication Error with NPCI', 
        'E0835' :'The order already exists in the database', 
        'E0836' :'General Error Rejected by NPCI', 
        'E0837' :'Invalid credit card number', 
        'E0838' :'Invalid amount', 
        'E0839' :'Duplicate Data Posted', 
        'E0840' :'Format error', 
        'E0841' :'SYSTEM ERROR', 
        'E0842' :'Invalid expiration date', 
        'E0843' :'Session expired for this transaction', 
        'E0844' :'FRAUD - Purchase limit exceeded', 
        'E0845' :'Verification decline', 
        'E0846' :'Compliance error code for issuer', 
        'E0847' :'Caught ERROR of type:[ System.Xml.XmlException ] . strXML is not a valid XML string', 
        'E0848' :'Incorrect personal identification number', 
        'E0849' :'Stolen card', 
        'E0850' :'Transaction timed out, please retry', 
        'E0851' :'Failed in Authorize - PE', 
        'E0852' :'Cardholder did not return from Rupay', 
        'E0853' :'Missing Mandatory Field(s)The field card_number has exceeded the maximum length of', 
        'E0854' :'Exception in CheckEnrollmentStatus: Data at the root level is invalid. Line 1, position 1.', 
        'E0855' :'CAF status = 0 or 9', 
        'E0856' :'412', 
        'E0857' :'Allowable number of PIN tries exceeded', 
        'E0858' :'No such issuer', 
        'E0859' :'Invalid Data Posted', 
        'E0860' :'PREVIOUSLY AUTHORIZED', 
        'E0861' :'Cardholder did not return from ACS', 
        'E0862' :'Duplicate transmission', 
        'E0863' :'Wrong transaction state', 
        'E0864' :'Card acceptor contact acquirer',
    }

    return rc.get(code, 'Unknown Error')

@app.route('/')
def home():
    return render_template('index.html')
@app.route('/national_committee')
def national_committee():
    return render_template('national-committe.html')



@app.route('/ima_ap_state_committee')
def ima_ap_state_committee():
    return render_template('ima-ap-state-committe.html')




@app.route('/mission_statement')
def mission_statement():
    return render_template('mission-statement.html')



@app.route('/rules_nav')
def rules_nav():
    return render_template('rules.html')



@app.route('/contact')
def contact():
    return render_template('contact.html')



@app.route('/venue_sports_schedule')
def venue_sports_schedule():
    return render_template('schedule.html')



@app.route('/games_subgames')
def games_subgames():
    return render_template('games.html')



@app.route('/terms_conditions')
def terms_conditions():
    return render_template('terms_conditions.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy-policy.html')


@app.route('/refund_returns')
def refund_returns():
    return render_template('refund-returns.html')




@app.route('/rules', methods=['GET', 'POST'])
def rules():

    if request.method == 'POST':
        if 'accept' in request.form:
            user_accept =request.form['accept']
            return redirect(url_for('register', user_accept=user_accept))
        else:
            user_accept = False
            return render_template('rules1.html')

    return render_template('rules1.html')

@app.route('/register/<user_accept>', methods=['GET', 'POST'])
def register(user_accept):
    if user_accept=='Yes':

        if request.method == 'POST':
            acception = user_accept
            fname = request.form['fname']
            lname = request.form['lname']
            email = request.form['email']
            password = request.form['password']
            mobile = request.form['mobile']
            age = request.form['age']
            gender = request.form['gender']
            dob = request.form['dob']
            city = request.form['city']
            address = request.form['address']
            state = request.form['state']
            country = request.form['country']
            degree = request.form['degree']
            mci = request.form['mci']
            game = request.form['game']
            selectmember = request.form['selectmember']
            shirtsize = request.form['shirtsize']
            otp=request.form['otp']
            dobfile=request.files['dobfile']
            cursor = mydb.cursor(buffered=True)
            # cursor.execute('SELECT COUNT(*) FROM register WHERE CONCAT(FirstName, " ", LastName) = %s', [full_name])
            # count = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM register WHERE Email = %s', [email])
            count1 = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM register WHERE mobileno = %s', [mobile])
            count2 = cursor.fetchone()[0]
            cursor.close()
            if count2 == 1:
                message='Mobile number already exists.'

                return render_template('register.html',message=message)
            if count1 == 1:
                message='Email already in use'
                return render_template('register.html',message=message)
            cond=True if session.get('email') else False
            if cond!=True:
                message='Please verify your email'
                return render_template('register.html',message=message)
            if session['otp']!=otp:
                message='Invalid OTP'
                return render_template('register.html',message=message)
            if session.get('email')!=request.form['email']:
                message='Email address changed verify otp again'
                return render_template('register.html',message=message)
            # Get the uploaded certificate and photo files
            certificate_file = request.files['certificate']
            photo_file = request.files['photo']

            # Generate unique filenames for certificate and photo using UUID
            certificate_filename = f'{mobile}.{certificate_file.filename.split(".")[-1]}'
            photo_filename = f'{mobile}.{photo_file.filename.split(".")[-1]}'
            dob_filename = f'{mobile}.{dobfile.filename.split(".")[-1]}'


            # Save the certificate and photo files to the upload folder
            certificate_file.save(os.path.join(app.config['UPLOAD_FOLDER'], certificate_filename))
            photo_file.save(os.path.join(app.config['UPLOAD_FOLDERS'], photo_filename))
            dobfile.save(os.path.join(app.config['UPLOAD_FOLDERSS'], dob_filename))

            
            if selectmember == 'IMA Member':
                amount = 3500
            else:
                amount = 4000
            
            full_name = fname + ' ' + lname  # Combine first name and last name

            
            # Hash the password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            

            data = {
                'fname': fname, 'lname': lname, 'email': email, 'password': hashed_password, 'mobile': mobile,
                'age': age, 'gender': gender, 'dob': dob, 'city': city, 'address': address, 'state': state,
                'country': country, 'degree': degree, 'mci': mci, 'game': game, 'selectmember': selectmember,
                'acception': acception, 'amount': amount,'shirtsize': shirtsize,
            }
            cursor=mydb.cursor(buffered=True)
            cursor.execute('INSERT INTO register(FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,member,shirt_size,acception) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', [data['fname'], data['lname'], data['email'], data['password'], data['mobile'], data['age'], data['gender'], data['dob'], data['city'], data['address'], data['state'], data['country'], data['degree'], data['mci'], data['selectmember'],data['shirtsize'], data['acception']])
            cursor.execute('select id from register where email=%s', [data['email']])
            eid=cursor.fetchone()[0]
            cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [eid,data['game'],data['amount']])
            print(game)
            
            mydb.commit()
            cursor.close()
            session.pop('otp')
            session.pop('email')
            session['user']=eid
            flash ('Registration successful! Complete the payment process.')
            subject='IMA Doctors Olympiad Registration'
            body=f'Thanks for the registration your unique for future reference is {eid}'
            sendmail(to=email, subject=subject, body=body)
            return redirect(url_for('payment',eid=eid,game=data['game'],))
        return render_template('register.html',message='')
    else:
        abort(404,'Page not found')
         
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mydb.cursor(buffered=True)
        cursor.execute('SELECT * FROM register WHERE Email = %s', [email])
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Check the hashed password with the entered password
            if bcrypt.check_password_hash(user[4], password):
                # Log the user in by setting the 'user' in the session

                # Check if the status is 'success'
                if user[18] == 'success':
                    session['user'] = user[0]
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                    # return('Ram ram')
                else:
                    cursor = mydb.cursor(buffered=True)
                    cursor.execute('select id from register where email=%s', [email])
                    eid=cursor.fetchone()[0]
                    cursor.execute('SELECT game,amount FROM game where id=%s', [eid])
                    game,amount=cursor.fetchone()
                    cursor.close()
                    # If the status is not 'success', redirect to the payment page
                    return redirect(url_for('payment',game=game,eid=eid))

            else:
                flash('Invalid password! Please try again.', 'error')
        else:
            flash('User not found! Please check your email and try again.', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    if session.get('user'):
        session.pop('user')
        return redirect(url_for('home'))
    else:
        flash("already logged out")
        return redirect(url_for('login'))


@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    # Handle the form data and generate OTP
    data = request.form
    email = data['email']
    #address = data['address']
    # Generate a random OTP (For simplicity, using a 6-digit OTP)
    otp = ''.join(random.choices('0123456789', k=6))
    print(otp)
    if 'email' in session:
        session.pop('email')
        session.pop('otp')
        session['email']=email
        session['otp']=otp
    else:
        session['email']=email
        session['otp']=otp
    subject = 'Email Confirmation'
    body = f"Your One Time Password for Registration is {otp}\n\nThanks & Regards\nIMA Doctors Olympiad"
    sendmail(to=email, subject=subject, body=body)
    return jsonify({'message': 'OTP has been sent to your email.OTP expires in 15 minutes.'})


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        cursor = mydb.cursor(buffered=True)
        cursor.execute('SELECT COUNT(*) FROM register WHERE Email=%s', [email])
        count = cursor.fetchone()[0]
        cursor.close()

        if count == 0:
            flash('Email not found. Please enter a registered email.')
            return render_template('forgot_password.html')

        # Generate a one-time token for password reset
        serializer = URLSafeTimedSerializer(secret_key)
        token = serializer.dumps(email, salt=salt2)

        # Send the reset link to the user's email
        subject = 'Password Reset Link'
        body = f"Please follow this link to reset your password: {url_for('reset_password', token=token, _external=True)}"
        sendmail(to=email, subject=subject, body=body)

        flash('Password reset link sent to your email.')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        serializer = URLSafeTimedSerializer(secret_key)
        email = serializer.loads(token, salt=salt2, max_age=180)
    except Exception as e:
        flash('Invalid or expired token. Please request a new password reset.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        # Validate and update the new password
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return render_template('reset_password.html', token=token)

        # Hash the new password using bcrypt
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        cursor = mydb.cursor(buffered=True)
        cursor.execute('UPDATE register SET password=%s WHERE Email=%s', [hashed_password, email])
        mydb.commit()
        cursor.close()

        flash('Password reset successful. You can now log in with your new password.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/checkout-order-pay/<eid>/<game>', methods=['GET', 'POST'])
def payment(eid,game):
    cursor = mydb.cursor(buffered=True)
    cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo, member FROM register WHERE id=%s", [eid])
    data1 = cursor.fetchall()
    cursor.execute('SELECT status from register WHERE id=%s', [eid])
    status=cursor.fetchone()[0]
    cursor.execute('SELECT email from register where id=%s',[eid])
    email=cursor.fetchone()[0]
    cursor.execute("select CONCAT(FirstName, ' ', LastName) AS FullName from register where id=%s",[eid])
    name=cursor.fetchone()[0]
    if status=='pending':
        cursor.execute("SELECT game, amount FROM game WHERE id=%s", [eid])
        cursor.close()
        game,amount = cursor.fetchone()
    else:
        cursor.execute('select amount from games where game_name=%s',[game])
        amount=cursor.fetchone()[0]
        cursor.close()
    ref=random.randint(1000000,99999999)
    eazypay_integration = Eazypay(eid,game,ref)
    payment_url=eazypay_integration.get_payment_url(ref,amount,name,email,data1[0][3])
    print(data1[0][2])
    print(payment_url)
    if request.method=='POST':
        return redirect(payment_url)
    return render_template('payment.html', data1=data1,game=game,amount=amount,eid=eid,ref=ref,name=name,email=email,payment_url=payment_url)


# @app.route('/pay/<eid>/<game>/<ref>',methods=['POST'])
# def pay(eid,game,ref):
#     cursor = mydb.cursor(buffered=True)
#     cursor.execute('SELECT status from register WHERE id=%s', [eid])
#     status=cursor.fetchone()[0]
#     if status=='pending':
#         cursor.execute('SELECT amount FROM game WHERE id=%s', [eid])
#         amount = cursor.fetchone()[0]
#         cursor.close()
#     else:
#         cursor.execute('select amount from games where game_name=%s',[game])
#         amount=cursor.fetchone()[0]
#         #q=int(request.form['qty'])
#     q = 1
#     checkout_session=stripe.checkout.Session.create(
#         success_url=url_for('success',eid=eid,game=game,amount=amount,ref=ref,_external=True),
#         line_items=[
#             {
#                 'price_data': {
#                     'product_data': {
#                         'name': game,
#                     },
#                     'unit_amount': amount*100,
#                     'currency': 'inr',
#                 },
#                 'quantity':q
#             },
#             ],
#         mode="payment",)
#     return redirect(checkout_session.url)


@app.route('/purchase-summary/order-received/<eid>/<game>/<ref>',methods=['POST'])
def success(eid,ref,game):
    response = request.form.to_dict()
    print(response)
    response_code_value = response.get('Response Code','na')
    print(response_code_value)
    if response_code_value != 'na':
        if payment_success_exec():
            print(response)
            # Payment is successful
            return render_template('thank-you.html')
        else:
            # Payment failed, show failure message
            response_msg = get_response_message(response['Response Code'])
            print(response_msg)
            if response_code_value == 'E000':
                amount = float(response['Total Amount'])
                cursor = mydb.cursor(buffered=True)
                cursor.execute('SELECT status from register WHERE id=%s', [eid])
                status=cursor.fetchone()[0]
                cursor.execute('select gender from register where id=%s',[eid])
                gender=cursor.fetchone()[0]
                if status=='pending':
                    cursor.execute('update register set status=%s WHERE ID=%s',['success',eid])
                    cursor.execute('INSERT into payments (ordid,id,game,amount) VALUES (%s,%s,%s,%s)',[ref,eid,game,amount])
                    if game in ('CHESS','ROWING','FENCING','CYCLOTHON','ARCHERY','ROLLER SKATING'):
                            category="Men's singles" if gender=='Male' else "Women's singles"
                            cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,eid,category])
                    mydb.commit()
                    cursor.close()
                    flash('Payment Successful ! Login in to continue.')
                    return redirect(url_for('dashboard'))
                else:
                    cursor.execute('INSERT into payments (ordid,id,game,amount) VALUES (%s,%s,%s,%s)',[ref,eid,game,amount])
                    cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [eid,game,amount])
                    if game in ('CHESS','ROWING','FENCING','CYCLOTHON','ARCHERY','ROLLER SKATING'):
                            category="Men's singles" if gender=='Male' else "Women's singles"
                            cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,eid,category])
                    mydb.commit()
                    cursor.close()
                    flash('Payment Successful')
                    return redirect(url_for('dashboard'))
            else:
                return f"<h1>Transaction failed. Error: {response_msg}</h1>"
    else:
        # 'Response_Code' key is missing in the response
        return "Invalid response received from payment gateway."



'''@app.route('/dashboard')
def dashboard():
    if session.get('user'):
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo, member, status FROM register WHERE id=%s", [session.get('user')])
        user_data = cursor.fetchone()
        cursor.execute("SELECT game, amount FROM game where id=%s", [session.get('user')])
        game,amount = cursor.fetchone()
        cursor.close()
        

        if user_data[5] == 'success':
            # User has completed the payment successfully
            return render_template('dashboard.html', user_data=user_data,game=game,amount=amount)
        else:
            # User hasn't completed the payment, redirect to the payment page
            flash('Complete your payment to access the dashboard.', 'info')
            return redirect(url_for('payment'))
    else:
        flash('You must log in to access the dashboard.', 'error')
        return redirect(url_for('login'))'''


@app.route('/sport/<game>',methods=['GET','POST'])
def sport(game):
    if session.get('user'):
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select count(*) from game where game=%s and id=%s',[game,session.get('user')])
        count = cursor.fetchone()[0]
        cursor.execute('select gender from register where id=%s',[session.get('user')])
        gender=cursor.fetchone()[0]
        cursor.execute('select email from register where id=%s',[session.get('user')])
        email_id=cursor.fetchone()[0]
        cursor.close()
        if count==0:
            return redirect(url_for('payment',eid=session.get('user'),game=game))
        else:
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
            count=cursor.fetchone()[0]
            cursor.close()
            if count==0:
                if game in ('ATHLETICS','ARCHERY','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER_SKATING','FENCING','SHOOTING'):
                    if request.method=='POST':
                        cursor = mydb.cursor(buffered=True)
                        for i in request.form:
                            cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                        mydb.commit()
                        cursor.close()
                        subject='Doctors Olympiad Games registration'
                        body=f'You are successfully registered to {" ".join(request.form.values())}\n\nThanks and regards\nDoctors Olympiad 2023'
                        sendmail(email_id,subject,body)
                        return redirect(url_for('dashboard'))
                    return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
                else:
                    if request.method=='POST':
                        return '<h1>Updates are on the way see you soon</h1>'

                    return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
                    #pass




            elif count>=1:
                if game in ('ATHLETICS','ARCHERY','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER_SKATING','FENCING','SHOOTING'):
                    flash('You already registered for this game')
                    return redirect(url_for('individual'))
                else:
                    return game
    else:
        return redirect(url_for('login'))
@app.route('/dashboard')
def dashboard():
    if session.get('user'):
        cursor = mydb.cursor(buffered=True)
        cursor.execute('SELECT game_name from games where game_name not in (select game from game where id=%s)',[session.get('user')])
        add_games=cursor.fetchall()
        cursor.execute('SELECT game from game where id=%s',[session.get('user')])
        games=cursor.fetchall()
        cursor.close()
        '''cursor.execute('select count(*) from game where game=%s and id=%s',[game,session.get('user')])
        count = cursor.fetchone()[0]
        cursor.execute('select gender from register where id=%s',[session.get('user')])
        gender=cursor.fetchone()[0]
        cursor.execute('select email from register where id=%s',[session.get('user')])
        email_id=cursor.fetchone()[0]
        cursor.close()'''
        return render_template('my-account.html',games=games,add_games=add_games)
    else:
        return redirect(url_for('login'))
@app.route('/edit',methods=['GET','POST'])
def edit_profile():
    if session.get('user'):
        cursor=mydb.cursor(buffered=True)
        eid=session.get('user')
        cursor.execute("select * from register where id =%s",[eid])
        data=cursor.fetchone()
        print('user id',session.get('user'))
        print('user data',data)
        cursor.execute("select mobileno from register where id =%s",[eid])
        mobile=cursor.fetchone()[0]
        print('mobile',mobile)
        cursor.close()
        print('all Photos',os.listdir(os.path.join(os.path.dirname(os.path.abspath(__file__)),'static','uploads','photos')))
        for i in os.listdir(os.path.join(os.path.dirname(os.path.abspath(__file__)),'static','uploads','photos')):
            print(i.split('.')[0])
            if i.split('.')[0]==str(mobile):
                filename=i
        if request.method=='POST':
            firstname=request.form['fname']
            print(firstname)
            lastname=request.form['lname']
            email=request.form['email']
            mobile=request.form['mobile']
            age=request.form['age']
            gender=request.form['gender']
            dob=request.form['dob']
            city=request.form['city']
            address=request.form['address']
            state=request.form['state']
            country=request.form['country']
            shirtsize=request.form['shirtsize']
            cursor=mydb.cursor(buffered=True)
            cursor.execute('update register set FirstName=%s,LastName=%s,Email=%s,mobileno=%s,age=%s,gender=%s,DOB=%s,city=%s,address=%s,state=%s,country=%s,SHIRT_SIZE=%s where id=230024',[firstname,lastname,email,mobile,age,gender,dob,city,address,state,country,shirtsize])
            mydb.commit()
            cursor.close()
            cursor=mydb.cursor(buffered=True)
            eid=session.get('user')
            cursor.execute("select * from register where id =%s",[eid])
            data=cursor.fetchone()
            cursor.execute("select mobileno from register where id =%s",[eid])
            mobile=cursor.fetchone()[0]
            cursor.close()
            flash('Profile updated')
        return render_template('edits.html',data=data,filename=filename)
    else:
        return redirect(url_for('login'))
@app.route('/all payments')
def payment_orders():
    if session.get('user'):
        cursor=mydb.cursor(buffered=True)
        eid=session.get('user')
        cursor.execute('select * from payments where id = %s',[eid])
        payment = cursor.fetchall()
        cursor.close()
        return render_template('Payments.html',payment = payment)
    else:
        return redirect(url_for('login'))
@app.route('/individual')
def individual():
    if session.get('user'):
        eid=session.get('user')
        a=['ATHLETICS','ARCHERY','BADMINTON','CARROM','CHESS','CYCLOTHON','JUMPS','SWIMMING','THROW','ROWING','ROLLER_SKATING','FENCING','TENNIKOIT','TABELTENNIS','LAWNTENNIS','BALL_BADMINTON']
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT * FROM sub_games WHERE id=%s",[eid])
        data1 = cursor.fetchall()
        cursor.close()
        data=[]
        for i in data1:
            if i[0] in a:
                data.append(i)
        return render_template('Individualgames.html',data=data)
    else:
        return redirect(url_for('login'))
@app.route('/team')
def team():
    if session.get('user'):
        eid=session.get('user')
        a=['BALL_BADMINTON','CRICKET_WHITE_BALL','HARD_TENNIS_CRICKET','WOMEN_BOX_CRICKET','VOLLEYBALL','FOOTBALL','KHO_KHO','KABADDI','THROW_BALLTUG_OF_WAR','BASKET_BALL']
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT * FROM sub_games WHERE id=%s",[eid])
        data1 = cursor.fetchall()
        cursor.close()
        data=[]
        for i in data1:
            if i[0] in a:
                data.append(i)
        return render_template('teams.html',data=data)
    else:
        return redirect(url_for('login'))

@app.route('/buyaddon/<game>')
def buyaddon(game):
    if session.get('user'):
        return redirect(url_for('payment',eid=session.get('user'),game=game))
    else:
        return redirect(url_for('login'))
@app.route('/registeredgame/<game>',methods=['GET','POST'])
def registeredgame(game):
    cursor = mydb.cursor(buffered=True)
    cursor.execute('select gender from register where id=%s',[session.get('user')])
    gender=cursor.fetchone()[0]
    cursor.execute('select email from register where id=%s',[session.get('user')])
    email_id=cursor.fetchone()[0]
    cursor.close()
    if game in ('ARCHERY','CHESS','CYCLOTHON','TENNKOIT','THROW','ROWING','ROLLER_SKATING','FENCING'):
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
        count = cursor.fetchone()[0]
        cursor.close()
        if count>=1:
            flash('Already registered!refer your games profile')
            return redirect(url_for('individual'))
        if request.method=='POST':
            cursor = mydb.cursor(buffered=True)
            for i in request.form:
                cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                mydb.commit()
            cursor.close()
            subject='Doctors Olympiad Games registration'
            body=f'You are successfully registered to {" ".join(request.form.values())}\n\nThanks and regards\nDoctors Olympiad 2023'
            sendmail(email_id,subject,body)
            return redirect(url_for('individual'))
        return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
    elif game =='JUMPS':
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
        count = cursor.fetchone()[0]
        cursor.close()
        if count>=1:
            flash('Already registered!refer your games profile')
            return redirect(url_for('dashboard'))
        if request.method=='POST':
            if len(request.form)==0:
                flash('Please select atleast one category')
            else:
                cursor = mydb.cursor(buffered=True)
                for i in request.form:
                    cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                    mydb.commit()
                cursor.close()
                subject='Doctors Olympiad Games registration'
                body=f'You are successfully registered to {" ".join(request.form.values())}\n\nThanks and regards\nDoctors Olympiad 2023'
                sendmail(email_id,subject,body)
                return redirect(url_for('dashboard'))
        return render_template(f'/games-individual-team/Individual/{game}.html')
    elif game=='SWIMMING':
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
        count = cursor.fetchone()[0]
        cursor.close()
        if count>=1:
            flash('Already registered!refer your games profile')
            return redirect(url_for('dashboard'))
        if request.method=='POST':
            s_styles={'Butterfly Stroke','Breaststroke','Backstroke','Freestyle'}
            b_tracks={'50m-Butterfly Stroke','100m-Butterfly Stroke','200m-Butterfly Stroke'}
            s_tracks={'50m-Breaststroke','100m-Breaststroke','200m-Breaststroke'}
            t_tracks= {'50m-Backstroke','100m-Backstroke','200m-Backstroke'}
            f_tracks={'50m-Freestyle','100m-Freestyle','200m-Freestyle'}

            styles={i for i in request.form.keys() if i in s_styles}
            if len(styles)==0:
                flash('Select a category')
                return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
            values=set(request.form.values())
            form_values=values.difference(s_styles)
            for i in styles:
                if i=='Butterfly Stroke':
                    result1=b_tracks.difference(form_values)
                    if len(result1)==3:
                        flash('Select atleast one of the sub category')
                        break
                elif i=='Breaststroke':
                    result2=s_tracks.difference(form_values)
                    if len(result2)==3:
                        flash('Select atleast one of the sub category')
                        break
                elif i=='Freestyle':
                    result3=t_tracks.difference(form_values)
                    if len(result3)==3:
                        flash('Select atleast one of the sub category')
                        break
                elif i=='Backstroke':
                    result4=f_tracks.difference(form_values)
                    if len(result4)==3:
                        flash('Select atleast one of the sub category')
                        break
            else:
                cursor = mydb.cursor(buffered=True)
                for i in form_values:
                    cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                    mydb.commit()
                cursor.close()
                flash('Details Registered Successfully ')
                subject='Doctors Olympiad Games registration'
                body=f'You are successfully registered to {"/n".join(values)}\n\nThanks and regards\nDoctors Olympiad 2023'
                sendmail(email_id,subject,body)
                return redirect(url_for('dashboard'))
        return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)

    elif game=='ATHLETICS':
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
        count = cursor.fetchone()[0]
        cursor.execute('select gender from register where id=%s',[session.get('user')])
        gender=cursor.fetchone()[0]
        cursor.close()
        if count>=1:
            flash('Already registered!refer your games profile')
            return redirect(url_for('dashboard'))
        if request.method=='POST':
            print(request.form)
            a_styles={'Sprint', 'Pole Vault', 'Walkathon','Marathon'}
            styles={i for i in request.form.keys() if i in a_styles}
            values=set(request.form.values())
            form_values=values.difference(a_styles)
            print(form_values)
            s_styles={'100m Sprint', 'Sprint', '200m Sprint', '400m Sprint', '800m Sprint'}
            p_styles={'100 m Hurdles Pole Vault', '4 x 100 m Relay Pole Vault'}
            d_styles={"Men's 10 km Walkathon","Women's 10 km Walkathon"}
            f_styles={"Men's 10 km Marathon", "Men's 21 km Marathon","Women's 10 km Marathon", "Women's 21 km-Marathon"}
        

            if len(styles)==0:
                flash('Select a category')
                return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
            for i in styles:
                if i=='Sprint':
                    result1=s_styles.difference(form_values)
                    if len(result1)==len(s_styles):
                        flash('Select atleast one of the sub category')
                        break
                elif i=='Pole Vault':
                    result2=p_styles.difference(form_values)
                    if len(result2)==len(p_styles):
                        flash('Select atleast one of the sub category')
                        break
                elif i=='Walkathon':
                    result3=d_styles.difference(form_values)
                    if len(result3)==len(d_styles):
                        flash('Select atleast one of the sub category')
                        break
                elif i=='Marathon':
                    result4=f_styles.difference(form_values)
                    if len(result4)==len(f_styles):
                        flash('Select atleast one of the sub category')
                        break
            else:
                cursor = mydb.cursor(buffered=True)
                for i in form_values:
                    cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                    mydb.commit()
                cursor.close()
                flash('Details Registered Successfully ')
                subject='Doctors Olympiad Games registration'
                body=f'You are successfully registered to {" ".join(values)}\n\nThanks and regards\nDoctors Olympiad 2023'
                sendmail(email_id,subject,body)
                return redirect(url_for('dashboard'))
        return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
    
    elif game in ('BADMINTON','TABLETENNIS','LAWNTENNIS','CARROMS'):
        singles=["Women's Single","Men's Single"]
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select category from sub_games where game=%s and id=%s',[game,session.get('user')])
        singles_data=cursor.fetchall()
        cursor = mydb.cursor(buffered=True)
        cursor.execute('''SELECT status from teams as t inner join sub_games as s on t.teamid=s.team_number where game=%s''',[game])
        cursor.close()
        data=[i[0] for i in cursor.fetchall() if i[0]=='Pending']
        cond=True
        
        if len(singles_data)==1:
            if singles_data[0] in singles:
                cond=False
        else:
            cond=False
        if len(data)==0 and cond:
            flash('Already registered refer to games section')
            return redirect(url_for('dashboard'))
        if len(data)!=0:
            pass

        if request.method=='POST':
            if len(request.form.keys())==1:
                if list(request.form.keys())[0] in singles:
                    cursor = mydb.cursor(buffered=True)
                    for i in request.form.values():
                        cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                        mydb.commit()
                    cursor.close()
                    flash('Details Registered Successfully ')
                    subject='Doctors Olympiad Games registration'
                    body=f'You are successfully registered to {" ".join(request.form.values())}\n\nThanks and regards\nDoctors Olympiad 2023'
                    sendmail(email_id,subject,body)
                    return redirect(url_for('dashboard'))
            else:
                pass

        return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
    else:
        return render_template(f'/games-individual-team/Team/{game}.html',gender=gender)


@app.route('/pays')
def pays():
    return render_template('eazy.html')

@app.route('/checkout/order-pay/<nam>/<int:numbr>')
def paymentsss(nam,numbr):
    return render_template('payment_form.html')

def validate_form(amount):
    if amount < 0:
        return False
    return True


@app.route('/checkout/order-pay/<nam>/<int:numbr>', methods=['POST'])
def process_payment(nam,numbr):
    session['payer_name'] = request.form['payername']
    session['payer_phone'] = request.form['payerphone']
    session['payer_email'] = request.form['payeremail']
    amount = int(request.form['payeramount'])
    name = session['payer_name']
    email = session['payer_email']
    phone = session['payer_phone']

    if not validate_form(amount):
        return "Amount should be greater than Rs.10"

    # Create an instance of Eazypay with the encryption key
    eazypay_integration = Eazypay()

    # reference_no = 8001  # You can use a random number generator if you prefer
    reference_no = str(random.randint(100000, 999999))

    # Store the necessary data in the session to verify the payment later
    session['reference_no'] = reference_no
    session['amount'] = amount
    session['name'] = name
    session['email'] = email
    session['phone'] = phone

    payment_url = eazypay_integration.get_payment_url(reference_no, amount, name, email, phone)
    print(payment_url)
    
    return redirect(payment_url)



@app.route('/purchase-summary/order-received/', methods=['POST'])
def response_handler():
    response = request.form.to_dict()
    print(response)
    response_code_value = response.get('Response Code','na')
    print(response_code_value)
    if response_code_value != 'na':
        if payment_success_exec():
            print(response)
            # Payment is successful
            return render_template('thank-you.html')
        else:
            # Payment failed, show failure message
            response_msg = get_response_message(response['Response Code'])
            print(response_msg)
            return f"Transaction failed. Error: {response_msg}"
    else:
        # 'Response_Code' key is missing in the response
        return "Invalid response received from payment gateway."



if __name__ == '__main__':
    app.run()
