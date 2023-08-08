from flask import Flask, request, redirect, render_template, url_for, flash,session,abort,jsonify
import flask_excel as excel
from flask_session import Session
from teamuniqueid import genteamid,adotp
import mysql.connector
import random
from io import BytesIO
from key import secret_key, salt, salt2
from itsdangerous import URLSafeTimedSerializer
from stoken import token,token2
from cmail import sendmail,mail_with_atc
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
     #cursor.execute("alter table game modify game  enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR')")
     #cursor.execute("DROP TABLE games")
     #cursor.execute("ALTER TABLE payments drop foreign key payments_ibfk_1")
     cursor.execute("CREATE TABLE if not exists register (ID int NOT NULL AUTO_INCREMENT,FirstName varchar(25) DEFAULT NULL,LastName varchar(25) DEFAULT NULL,Email varchar(50) DEFAULT NULL,PASSWORD longblob,mobileno bigint DEFAULT NULL,age int DEFAULT NULL,gender varchar(10) DEFAULT NULL,DOB date DEFAULT NULL,city text,address text,state text,country text,degree varchar(10) DEFAULT NULL,MCI_ID varchar(20) DEFAULT NULL,member varchar(20) DEFAULT NULL,SHIRT_SIZE enum('S','M','L','XL','XXL','XXXL','XXXXL') DEFAULT NULL,acception varchar(30) DEFAULT 'No',status varchar(20) NOT NULL DEFAULT 'pending',PRIMARY KEY (ID),UNIQUE KEY Email (Email),UNIQUE KEY mobileno (mobileno))")
     cursor.execute("CREATE TABLE if not exists game (ID INT, game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),AMOUNT INT UNSIGNED)")
     cursor.execute("create table if not exists games(game_name varchar(30),amount int unsigned,team_count int)")
     # cursor.execute("insert into games values('ATHLETICS',1500,1),('ARCHERY',30,1),('BADMINTON',1500,2),('BASKETBALL',10000,9),('BALL BADMINTON',10000,7),('CARROMS',1500,2),('CHESS',30,1),('CYCLOTHON',30,1),('JUMPS',1500,1),('SWIMMING',1500,1),('THROW',1500,1),('ROWING',1500,1),('SHOOTING',1500,1),('ROLLER SKATING',1500,1),('FENCING',1500,1),('TENNIKOIT',1500,1),('TABLE TENNIS',1500,2),('LAWN TENNIS',1500,2),('CRICKET WHITE BALL',30000,14),('HARD TENNIS CRICKET',20000,14),('WOMEN BOX CRICKET',10000,7),('VOLLEY BALL',10000,9),('FOOTBALL',10000,11),('KHO KHO',10000,12),('KABADDI',10000,10),('THROWBALL',10000,10),('TUG OF WAR',5000,10)")
     cursor.execute("create table if not exists payments(ordid varchar(36),id int,game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),amount int unsigned,date timestamp default now() on update now(),foreign key(id) references register(id))")
     cursor.execute("CREATE TABLE if not exists sub_games (game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),id int ,category varchar(50),team_number int unique, date timestamp default current_timestamp on update current_timestamp,foreign key(id) references register(id))")
     cursor.execute("create table if not exists teams(teamid int,id int,status enum('Accept','Pending'),foreign key(teamid) references sub_games(team_number),foreign key(id) references register(id))")
     #cursor.execute("alter table payments modify ordid int unsigned")
     #cursor.execute("alter table payments modify amount decimal(8,3)")
     #cursor.execute("ALTER TABLE payments ADD status enum('pending','Successfull')  default 'pending' after amount")
     #cursor.execute("ALTER TABLE payments add transactionid bigint unsigned")
     #cursor.execute("create table temporary like register")
     #cursor.execute("ALTER TABLE temporary auto_increment=1000")
     #cursor.execute('ALTER TABLE register drop column status')
     #cursor.execute('ALTER TABLE temporary drop column status')
     #cursor.execute('alter table register auto_increment=230001')
     cursor.close()
mydb=mysql.connector.connect(host=host,user=user,password=password,db=db,pool_name='DED',pool_size=32)

stripe.api_key='sk_test_51NTKipSDmVNK7hRpj4DLpymMTojbp0sntuHknEF9Kv3cGY79VkNbmBcfxDmTLXa9UIGKiiqp8drQQhzsjoia58Sm00Kuzg9vYt'

# Configure the upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/certificates')
app.config['UPLOAD_FOLDERS'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/photos')
app.config['UPLOAD_FOLDERSS'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/dob')


bcrypt = Bcrypt(app)

class Eazypay:
    def __init__(self,return_url):
        self.merchant_id = '376890'
        self.encryption_key = b'3777003168901000'
        self.sub_merchant_id = '20'
        self.paymode = '9'
        self.return_url = return_url

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
        mandatory_fields = self.decrypt(mandatory_field)
        # optional_fields = self.decrypt(optional_field)
        amounts = self.decrypt(amount)
        reference_nos = self.decrypt(reference_no)
        return_urls = self.decrypt(self.get_return_url())
        merchant_ids = self.decrypt(self.get_sub_merchant_id())
        pay_modes = self.decrypt(self.get_paymode())
        encrypted_url = (
            f"https://eazypay.icicibank.com/EazyPG?merchantid={self.merchant_id}"
            f"&mandatory fields={mandatory_field}&optional fields={optional_field}"
            f"&returnurl={self.get_return_url()}&Reference No={reference_no}"
            f"&submerchantid={self.get_sub_merchant_id()}&transaction amount={amount}"
            f"&paymode={self.get_paymode()}"
        )
        decrypted_url = (
            f"https://eazypay.icicibank.com/EazyPG?merchantid={self.merchant_id}"
            f"&mandatory fields={mandatory_fields}&optional fields={optional_field}"
            f"&returnurl={return_urls}&Reference No={reference_nos}"
            f"&submerchantid={merchant_ids}&transaction amount={amounts}"
            f"&paymode={pay_modes}"
        )
        print(decrypted_url)
        print(encrypted_url)

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
        aes_key_for_payment_success = '3777003168901000'  # Replace this with the actual key

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
            print(request.form)
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
                amount = 30
            else:
                amount = 35
            
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
            cursor.execute('INSERT INTO temporary(FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,member,shirt_size,acception) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', [data['fname'], data['lname'], data['email'], data['password'], data['mobile'], data['age'], data['gender'], data['dob'], data['city'], data['address'], data['state'], data['country'], data['degree'], data['mci'], data['selectmember'],data['shirtsize'], data['acception']])
            mydb.commit()
            cursor.execute('select id from temporary where Email=%s and mobileno=%s', [data['email'], data['mobile']])
            eid=cursor.fetchone()[0]

            #updated code------------------------- --------------------------------
            #cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [eid,data['game'],data['amount']])
            #print(game)
            
            cursor.close()
            session.pop('otp')
            session.pop('email')
            #flash ('Registration successful! Complete the payment process.')
            #subject='IMA Doctors Olympiad Registration'
            #body=f'Thanks for the registration your unique for future reference is {eid}'
            #sendmail(to=email, subject=subject, body=body)
            #---------------------------------------------------------------
            link=url_for('payment',eid=eid,game=data['game'],amount=amount,_external=True)
            return redirect(link)
        return render_template('register.html',message='')
    else:
        abort(404,'Page not found')

@app.route('/registeronteam')
def registeronteam():
     if session.get('user'):
          flash("You Cannot Create a Team.Contact team lead to add you")
          return redirect(url_for('dashboard'))
     else:
          return redirect(url_for('login'))
         
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
                session['user'] = user[0]
                # Log the user in by setting the 'user' in the session
                return redirect(url_for('dashboard'))
                    # return('Ram ram')
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
    cursor=mydb.cursor(buffered=True)
    cursor.execute('select count(*) from register where email=%s',[email])
    count=cursor.fetchone()[0]
    cursor.close()
    if count==0:
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
        body = f"Your One Time Password for Registring for IMA Doctors Olympiad is: {otp}\n\nThanks & Regards\nIMA Doctors Olympiad"
        sendmail(to=email, subject=subject, body=body)
        return jsonify({'message': 'OTP has been sent to your email.OTP expires in 15 minutes.'})
    else:
        return jsonify({'message': 'Email already in use'})


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


@app.route('/checkout-order-pay/<eid>/<game>/<amount>', methods=['GET', 'POST'])
def payment(eid,game,amount):
    cursor = mydb.cursor(buffered=True)
    cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo, member FROM temporary WHERE id=%s", [eid])
    data1 = cursor.fetchall()
    cursor.execute('SELECT email from temporary where id=%s',[eid])
    email=cursor.fetchone()[0]
    cursor.execute("select CONCAT(FirstName, ' ', LastName) AS FullName from temporary where id=%s",[eid])
    name=cursor.fetchone()[0]
    # print(payment_url)
    if request.method=='POST':
        ref=random.randint(1000000,99999999)
        eazypay_integration = Eazypay(url_for('success',_external=True))
        payment_url=eazypay_integration.get_payment_url(ref,amount,name,email,data1[0][3])
        cursor  = mydb.cursor(buffered=True)
        cursor.execute('select count(*) from games where game_name=%s',[game])
        cursor.execute('insert into payments (ordid,id,game,amount) values(%s,%s,%s,%s)',[ref,eid,game,amount])
        mydb.commit()
        cursor.close()
        return jsonify({'status':'success','payment_url':payment_url})
    return render_template('payment.html', data1=data1,game=game,amount=amount,eid=eid,name=name,email=email)


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


@app.route('/success',methods=['POST'])
def success():
    response = request.form.to_dict()
    print(response)
    response_code_value = response.get('Response Code','na')
    print(response_code_value)
    if response_code_value != 'na':
        if payment_success_exec():
            ref = int(response['ReferenceNo'])
            amount = float(response['Total Amount'])
            transaction_id = int(response['Unique Ref Number'])
            cursor = mydb.cursor(buffered=True)
            cursor.execute('SELECT id,game from payments where ordid=%s',[ref])
            eid,game=cursor.fetchone()
            #cursor.execute('SELECT status from register WHERE id=%s', [eid])
            #status=cursor.fetchone()[0]
            cursor.execute('select gender,email from temporary where id=%s',[eid])
            gender,email=cursor.fetchone()
            cursor.execute('insert into register (FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,member,shirt_size,acception) select FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,member,shirt_size,acception from temporary where id=%s',[eid])
            mydb.commit()
            cursor.execute('SELECT id from register where email=%s',[email])
            uid=cursor.fetchone()[0]
            cursor.execute('SELECT concat(FirstName," ",LastName) as name from register where email=%s',[email])
            name=cursor.fetchone()[0]
            cursor.execute('UPDATE  payments SET status=%s,amount=%s,id=%s,transactionid=%s WHERE ordid=%s',['Successfull',amount,uid,transaction_id,ref])
            cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [uid,game,amount])
            cursor.execute('DELETE FROM temporary where id=%s',[eid])
            mydb.commit()
            if game in ('CHESS','ROWING','FENCING','CYCLOTHON','ARCHERY','ROLLER SKATING'):
                 category="Men's singles" if gender=='Male' else "Women's singles"
                 cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,uid,category])
                 mydb.commit()
                 cursor.execute('select * from payments')
                 details = cursor.fetchall()
                 print(details)
            cursor.close()
            
            html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Registration Confirmation</title>
                <style>
                    table {{
                        margin: auto;
                    }}
                    img {{
                        margin-left: 30%;
                    }}
                    h1 {{
                        text-align: center;
                    }}
                    table, tr, th, td {{
                        border: 1px solid black;
                        border-collapse: collapse;
                    }}
                    th {{
                        text-align: left;
                    }}
                    td {{
                        width: 60%;
                    }}
                </style>
            </head>
            <body>
                <img src="https://i0.wp.com/codegnanprojects.wpcomstaging.com/wp-content/uploads/2023/07/IMA-NATIONAL-SPORTS-MEET-2023-LOGO.jpg?fit=768%2C421&ssl=1" width="40%"/>
                <h1>Hi {name},Thanks for registering to {game} in Doctors Olympiad 2023.Your Payment details</h1>
                <table cellpadding="10">
                    <tr>
                        <th>UNIQUE REFERENCE ID</th>
                        <td>{uid}</td>
                    </tr>
                    <tr>
                        <th>Name</th>
                        <td>{name}</td>
                    </tr>
                    <tr>
                        <th>email</th>
                        <td>{email}</td>
                    </tr>
                    <tr>
                        <th>Game</th>
                        <td>{game}</td>
                    </tr>
                    <tr>
                        <th>Transaction ID</th>
                        <td>{transaction_id}</td>
                    </tr>
                    <tr>
                        <th>Payment</th>
                        <td>{amount}</td>
                    </tr>
                </table>
            </body>
            </html>
            """
            session['user']=uid
            # subject = 'Payment Successful! From Doctors Olympiad 2023'
            # mail_with_atc(email,subject,html)
            subject='Registration Successful for Doctors Olympiad 2023'
            # body=f'Hi {name},\n\nThanks for registering to {game} in Doctors Olympiad 2023\n\n\n\nunique reference id:{uid}\nName: {name}\nRegistered game: {game}\nTransaction id: {transaction_id}\n\n\n\n\nThanks and Regards\nDoctors Olympiad 2023\n\n\nContact:+91 9759634567'
            mail_with_atc(to=email, subject=subject, html=html)
            
            flash('Payment Successful')
            return redirect(url_for('dashboard'))
            # print(response)
            # Payment is successful
            # return render_template('thank-you.html')
        else:
            # Payment failed, show failure message
            response_msg = get_response_message(response['Response Code'])
            print(response_msg)
            return f"<h1>Transaction failed. Error: {response_msg}</h1>"
    else:
        # 'Response_Code' key is missing in the response
        return "Invalid response received from payment gateway."

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
    print(session.get('user'))
    if session.get('user'):
        cursor = mydb.cursor(buffered=True)
        query1="""
        SELECT game_name 
        FROM games 
        WHERE game_name NOT IN (
            SELECT game FROM game WHERE id = %s
        ) AND game_name IN (
            'ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON',
            'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING',
            'TABLE TENNIS', 'LAWN TENNIS'
        )"""
        cursor.execute(query1,[session.get('user')])
        add_individual_games=cursor.fetchall()
        query2 = """
        SELECT game_name 
        FROM games 
        WHERE game_name NOT IN (
            SELECT game FROM game WHERE id = %s) AND game_name not IN (
            'ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON',
            'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING',
            'TABLE TENNIS', 'LAWN TENNIS')"""
        cursor.execute(query2,[session.get('user')])
        add_teams_games=cursor.fetchall()
        cursor.execute('SELECT game,amount from game where id=%s',[session.get('user')])
        games=cursor.fetchall()
        cursor.close()
        '''cursor.execute('select count(*) from game where game=%s and id=%s',[game,session.get('user')])
        count = cursor.fetchone()[0]
        cursor.execute('select gender from register where id=%s',[session.get('user')])
        gender=cursor.fetchone()[0]
        cursor.execute('select email from register where id=%s',[session.get('user')])
        email_id=cursor.fetchone()[0]
        cursor.close()'''
        return render_template('my-account.html',games=games,add_individual_games=add_individual_games,add_teams_games=add_teams_games)
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
         sport =game
         cursor=mydb.cursor(buffered=True)
         cursor.execute("SELECT amount from games where game_name=%s",[sport])
         amount=cursor.fetchone()[0]
         cursor.close()
         return redirect(url_for('addonpayment',eid=session.get('user'),game=game,amount=amount))
    else:
        return redirect(url_for('login'))
@app.route('/addonpayment/<eid>/<game>/<amount>',methods=['GET','POST'])
def addonpayment(eid,game,amount):
    cursor = mydb.cursor(buffered=True)
    cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo, member FROM register WHERE id=%s", [eid])
    data1 = cursor.fetchall()
    cursor.execute('SELECT email from register where id=%s',[eid])
    email=cursor.fetchone()[0]
    cursor.execute("select CONCAT(FirstName, ' ', LastName) AS FullName from register where id=%s",[eid])
    name=cursor.fetchone()[0]
    # print(payment_url)
    if request.method=='POST':
        ref=random.randint(1000000,99999999)
        #print(url_for('addonsuccess',eid=eid,game=game,_external=True))
        return_url=url_for('addonsuccess',eid=eid,game=game,_external=True)
        eazypay_integration = Eazypay(return_url)
        payment_url=eazypay_integration.get_payment_url(ref,amount,name,email,data1[0][3])
        cursor  = mydb.cursor(buffered=True)
        cursor.execute('insert into payments (ordid,id,game,amount) values(%s,%s,%s,%s)',[ref,eid,game,amount])
        mydb.commit()
        cursor.close()
        return jsonify({'status':'success','payment_url':payment_url})
    return render_template('pays.html', data1=data1,game=game,amount=amount,eid=eid,name=name,email=email)
@app.route('/addonsuccess/<eid>/<game>',methods=['POST'])
def addonsuccess(eid,game):
    uid=eid
    response = request.form.to_dict()
    print(response)
    response_code_value = response.get('Response Code','na')
    print(response_code_value)
    if response_code_value != 'na':
        if payment_success_exec():
            ref = int(response['ReferenceNo'])
            amount = float(response['Total Amount'])
            transaction_id = int(response['Unique Ref Number'])
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select gender,email from register where id=%s',[uid])
            gender,email=cursor.fetchone()
            cursor.execute('SELECT concat(FirstName," ",LastName) as name from register where id=%s',[uid])
            name=cursor.fetchone()[0]
            cursor.execute('UPDATE  payments SET status=%s,amount=%s,id=%s,transactionid=%s WHERE ordid=%s',['Successfull',amount,uid,transaction_id,ref])
            cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [uid,game,amount])
            mydb.commit()
            if game in ('CHESS','ROWING','FENCING','CYCLOTHON','ARCHERY','ROLLER SKATING'):
                 category="Men's singles" if gender=='Male' else "Women's singles"
                 cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,uid,category])
                 mydb.commit()
                 cursor.execute('select * from payments')
                 details = cursor.fetchall()
                 print(details)
            cursor.close()
            
            html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Registration Confirmation</title>
                <style>
                    table {{
                        margin: auto;
                    }}
                    img {{
                        margin-left: 30%;
                    }}
                    h1 {{
                        text-align: center;
                    }}
                    table, tr, th, td {{
                        border: 1px solid black;
                        border-collapse: collapse;
                    }}
                    th {{
                        text-align: left;
                    }}
                    td {{
                        width: 60%;
                    }}
                </style>
            </head>
            <body>
                <img src="https://i0.wp.com/codegnanprojects.wpcomstaging.com/wp-content/uploads/2023/07/IMA-NATIONAL-SPORTS-MEET-2023-LOGO.jpg?fit=768%2C421&ssl=1" width="40%"/>
                <h1>>Hi {name},Thanks for registering to {game} in Doctors Olympiad 2023.Your Payment details</h1>
                <table cellpadding="10">
                    <tr>
                        <th>UNIQUE REFERENCE ID</th>
                        <td>{uid}</td>
                    </tr>
                    <tr>
                        <th>Name</th>
                        <td>{name}</td>
                    </tr>
                    <tr>
                        <th>email</th>
                        <td>{email}</td>
                    </tr>
                    <tr>
                        <th>Game</th>
                        <td>{game}</td>
                    </tr>
                    <tr>
                        <th>Transaction ID</th>
                        <td>{transaction_id}</td>
                    </tr>
                    <tr>
                        <th>Payment</th>
                        <td>{amount}</td>
                    </tr>
                </table>
            </body>
            </html>
            """
            session['user']=uid
            # subject = 'Payment Successful! From Doctors Olympiad 2023'
            # mail_with_atc(email,subject,html)
            subject='Registration Successful for Doctors Olympiad 2023'
            # body=f'Hi {name},\n\nThanks for registering to {game} in Doctors Olympiad 2023\n\n\n\nunique reference id:{uid}\nName: {name}\nRegistered game: {game}\nTransaction id: {transaction_id}\n\n\n\n\nThanks and Regards\nDoctors Olympiad 2023\n\n\nContact:+91 9759634567'
            mail_with_atc(to=email, subject=subject, html=html)
            
            flash('Payment Successful')
            return redirect(url_for('dashboard'))
            # print(response)
            # Payment is successful
            # return render_template('thank-you.html')
        else:
            # Payment failed, show failure message
            response_msg = get_response_message(response['Response Code'])
            print(response_msg)
            return f"<h1>Transaction failed. Error: {response_msg}</h1>"
    else:
        # 'Response_Code' key is missing in the response
        return "Invalid response received from payment gateway."
     
@app.route('/registeredgame/<game>',methods=['GET','POST'])
def registeredgame(game):
    cursor = mydb.cursor(buffered=True)
    cursor.execute('select gender from register where id=%s',[session.get('user')])
    gender=cursor.fetchone()[0]
    cursor.execute('select email from register where id=%s',[session.get('user')])
    email_id=cursor.fetchone()[0]
    cursor.close()
    if game in ('ARCHERY','CHESS','CYCLOTHON','ROWING','ROLLER_SKATING','FENCING'):
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
    elif game in ['SHOOTING','THROW']:
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
        return "<center><h1> Updates are on the Way!</h1></center>"
        # cursor = mydb.cursor(buffered=True)
        # cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
        # count = cursor.fetchone()[0]
        # cursor.execute('select gender from register where id=%s',[session.get('user')])
        # gender=cursor.fetchone()[0]
        # cursor.close()
        # if count>=1:
        #     flash('Already registered!refer your games profile')
        #     return redirect(url_for('dashboard'))
        # if request.method=='POST':
        #     print(request.form)
        #     a_styles={'Sprint', 'Pole Vault', 'Walkathon','Marathon'}
        #     styles={i for i in request.form.keys() if i in a_styles}
        #     values=set(request.form.values())
        #     form_values=values.difference(a_styles)
        #     print(form_values)
        #     s_styles={'100m Sprint', 'Sprint', '200m Sprint', '400m Sprint', '800m Sprint'}
        #     p_styles={'100 m Hurdles Pole Vault', '4 x 100 m Relay Pole Vault'}
        #     d_styles={"Men's 10 km Walkathon","Women's 10 km Walkathon"}
        #     f_styles={"Men's 10 km Marathon", "Men's 21 km Marathon","Women's 10 km Marathon", "Women's 21 km-Marathon"}
        

        #     if len(styles)==0:
        #         flash('Select a category')
        #         return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
        #     for i in styles:
        #         if i=='Sprint':
        #             result1=s_styles.difference(form_values)
        #             if len(result1)==len(s_styles):
        #                 flash('Select atleast one of the sub category')
        #                 break
        #         elif i=='Pole Vault':
        #             result2=p_styles.difference(form_values)
        #             if len(result2)==len(p_styles):
        #                 flash('Select atleast one of the sub category')
        #                 break
        #         elif i=='Walkathon':
        #             result3=d_styles.difference(form_values)
        #             if len(result3)==len(d_styles):
        #                 flash('Select atleast one of the sub category')
        #                 break
        #         elif i=='Marathon':
        #             result4=f_styles.difference(form_values)
        #             if len(result4)==len(f_styles):
        #                 flash('Select atleast one of the sub category')
        #                 break
        #     else:
        #         cursor = mydb.cursor(buffered=True)
        #         for i in form_values:
        #             cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
        #             mydb.commit()
        #         cursor.close()
        #         flash('Details Registered Successfully ')
        #         subject='Doctors Olympiad Games registration'
        #         body=f'You are successfully registered to {" ".join(values)}\n\nThanks and regards\nDoctors Olympiad 2023'
        #         sendmail(email_id,subject,body)
        #         return redirect(url_for('dashboard'))
        # return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
     
    
    elif game in ('BADMINTON','TABLETENNIS','LAWNTENNIS','CARROMS'):
        return "<center><h1> Updates are on the way </h1></center>"
        # singles=["Women's Single","Men's Single"]
    #     cursor = mydb.cursor(buffered=True)
    #     cursor.execute('select category from sub_games where game=%s and id=%s',[game,session.get('user')])
    #     singles_data=cursor.fetchall()
    #     cursor = mydb.cursor(buffered=True)
    #     cursor.execute('''SELECT status from teams as t inner join sub_games as s on t.teamid=s.team_number where game=%s''',[game])
    #     cursor.close()
    #     data=[i[0] for i in cursor.fetchall() if i[0]=='Pending']
    #     cond=True
        
    #     if len(singles_data)==1:
    #         if singles_data[0] in singles:
    #             cond=False
    #     else:
    #         cond=False
    #     if len(data)==0 and cond:
    #         flash('Already registered refer to games section')
    #         return redirect(url_for('dashboard'))
    #     if len(data)!=0:
    #         pass

    #     if request.method=='POST':
    #         if len(request.form.keys())==1:
    #             if list(request.form.keys())[0] in singles:
    #                 cursor = mydb.cursor(buffered=True)
    #                 for i in request.form.values():
    #                     cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
    #                     mydb.commit()
    #                 cursor.close()
    #                 flash('Details Registered Successfully ')
    #                 subject='Doctors Olympiad Games registration'
    #                 body=f'You are successfully registered to {" ".join(request.form.values())}\n\nThanks and regards\nDoctors Olympiad 2023'
    #                 sendmail(email_id,subject,body)
    #                 return redirect(url_for('dashboard'))
    #         else:
    #             pass

    #     return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
    else:
        cursor=mydb.cursor(buffered=True)
        cursor.execute("SELECT count(*) from sub_games where id=%s and game=%s",[session.get('user'),game])
        count=cursor.fetchone()[0]
        if count==0:
            if request.method=='POST':
                for i in request.form:
                    if i.startswith('output'):
                        if request.form[i] in ("Id not found","User Gender doesnot match","User Registered to other team" ,'User already Registered in other cricket team','You cannot add yourself.','User already Registered in two teams'):
                            return jsonify({'message':request.form[i]})
                else:
                    names=[]
                    for i in request.form:
                        if i.startswith('input'):
                            if request.form[i].isdigit():
                                uid=request.form[i]
                                if uid not in names:
                                    names.append(uid)
                                else:
                                    return jsonify({'message':"You added a person twice"})
                            else:
                                cursor.execute("SELECT count(*) from register where email=%s",[request.form[i]])
                                count=cursor.fetchone()[0]
                                if count!=0:
                                    cursor.execute("SELECT id from register where email=%s",[request.form[i]])
                                    uid=cursor.fetchone()[0]
                                    if uid not in names:
                                        names.append(uid)
                                    else:
                                        return jsonify({'message':"You added a person twice"})
                    else:
                        team_id=genteamid()
                        cursor.execute('INSERT INTO sub_games (game,id,team_number) values(%s,%s,%s)',[game,session.get('user'),team_id])                  
                        mydb.commit()
                        for i in request.form:
                            if i.startswith('input'):
                                if request.form[i].isdigit(): 
                                    uid=request.form[i]
                                    requestid=adotp()
                                    cursor.execute("insert into teams (reqid,teamid,id,game) values(%s,%s,%s,%s)",[requestid,team_id,uid,game])
                                    mydb.commit()
                                    cursor.execute("SELECT email from register where id=%s",[uid])
                                    r_email=cursor.fetchone()[0]
                                    one_time_token=token2(team_id,requestid,salt=salt2)
                                    link=url_for('accept',token=one_time_token,_external=True)
                                    subject=f'Team Request for {game}'
                                    body=f"Hello,\n\n You can join our team by using the below url.\nPlease click on this link to join -{link}"
                                    sendmail(r_email,subject=subject,body=body)
                                else:
                                    cursor.execute("SELECT count(*) from register where email=%s",[request.form[i]])
                                    count=cursor.fetchone()[0]
                                    if count!=0:
                                        cursor.execute("SELECT id from register where email=%s",[request.form[i]])
                                        uid=cursor.fetchone()[0]
                                        requestid=adotp()
                                        cursor.execute("insert into teams (reqid,teamid,id,game) values(%s,%s,%s,%s)",[requestid,team_id,uid,game])
                                        mydb.commit()
                                        one_time_token=token2(team_id,requestid,salt=salt2)
                                        link=url_for('accept',token=one_time_token,_external=True)
                                        subject=f'Team Request for {game}'
                                        body=f"Hello,\n\n You can join our team by using the below url.\nPlease click on this link to join -{link}"
                                        sendmail(request.form[i],subject=subject,body=body)
                                    else:
                                        requestid=adotp()
                                        cursor.execute("insert into teams (reqid,teamid,game) values(%s,%s,%s)",[requestid,team_id,game])
                                        mydb.commit()
                                        one_time_token=token2(team_id,requestid,salt=salt2,email=request.form[i])
                                        link=url_for('accept',token=one_time_token,_external=True)
                                        subject=f'Team Request for {game}'
                                        body=f"Hello,\n\n Register to doctors olympiad and join our team by using this using the below url.\nPlease click on this link to join -{link}"
                                        sendmail(request.form[i],subject=subject,body=body)
                        else:
                            cursor.close()
                            return jsonify({'message':'Success','url':url_for('dashboard',_external=True)})
            return render_template(f'/games-individual-team/Team/{game}.html',gender=gender,game=game,count=count)
        else:
            if request.method=='POST':
                return "Updates are on the way"
            return render_template(f'/games-individual-team/Team/{game}.html',gender=gender,game=game,count=count)
          
@app.route('/acceptrequest/<token>')
def accept(token):
    return "Updates are on the way"
@app.route('/individualupdate/<game>',methods=['POST'])
def individual_update(game): 
    if session.get('user'):
        input_value = request.form["inputValue"]
        category=request.form['category']
        print(category)
        gender=request.form['gender']
        message=check_individual(gender,input_value,game,category)
        response = {'outputValue': message}
        return jsonify(response)
    else:
        return redirect(url_for('login'))

def update_teams(input_value,game,add_gender):
    cursor=mydb.cursor()
    if input_value.isdigit():
        cursor.execute('select count(*) from register where id=%s',[input_value])
        data=cursor.fetchone()[0]
        message=''
        if data==0:
            message="Id not found"
        else:
            cond=True
            cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[input_value,game,'Accept'])
            count=cursor.fetchone()[0]
            cursor.execute('SELECT gender from register where id=%s',[input_value])
            gend=cursor.fetchone()[0]
            if gend!=add_gender:
                cond=False
                message='User Gender doesnot match'
            if int(input_value)==session.get('user'):
                message='You cannot add yourself.'
            if count>0:
                cond=False
                message='User Registered to other team'
            cursor.execute("SELECT count(*) from teams where id=%s and status=%s",[input_value,'Accept'])
            count1=cursor.fetchone()[0]
            if count1>1:
                cond=False
                message='User already Registered in two teams'
            if game in ['CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET']:
                cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[input_value,game,'Accept'])
                count2=cursor.fetchone()[0]
                if count2!=0:
                    cond=False
                    message='User already Registered in other cricket team'
            if cond==True and  message!="You cannot add yourself.":
                cursor.execute("SELECT concat_ws(' ',FirstName,LastName) as fullname from register where id=%s",[input_value])
                message=cursor.fetchone()[0]
            
        
    else:
        cursor.execute('select count(*) from register where email=%s',[input_value])
        data=cursor.fetchone()[0]
        message=''
        if data==0:
            message="User not found with this email id"
        else:
            cond=True
            cursor.execute('SELECT id from register where Email=%s',[input_value])
            eid=cursor.fetchone()[0]
            cursor.execute('SELECT gender from register where id=%s',[eid])
            gend=cursor.fetchone()[0]
            cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[eid,game,'Accept'])
            count=cursor.fetchone()[0]
            if gend!=add_gender:
                cond=False
                message='User Gender doesnot match'
            if eid ==session.get('user'):
                message='You cannot add yourself.'
            if count>0:
                cond=False
                message='User Registered to other team'
            cursor.execute("SELECT count(*) from teams where id=%s and status=%s",[eid,'Accept'])
            count1=cursor.fetchone()[0]
            if count1>1:
                cond=False
                message='User already Registered in two teams'
            if game in ['CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET']:
                cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[eid,game,'Accept'])
                count2=cursor.fetchone()[0]
                if count2!=0:
                    cond=False
                    message='User already Registered in other cricket team'
            if cond==True and message!='You cannot add yourself.':
                cursor.execute("SELECT concat_ws(' ',FirstName,LastName) as fullname from register where id=%s",[eid])
                message=cursor.fetchone()[0]
    cursor.close()
    return message

@app.route('/update/<game>', methods=['POST'])
def update(game):
    if session.get('user'):
        input_value = request.form['inputValue']
        add_gender=request.form['gender']
        message=update_teams(input_value,game,add_gender)
        # Here, you can perform any necessary processing with the input data.
        # For simplicity, we'll just return the input value as the response.
        response = {'outputValue': message}
        return jsonify(response)
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()
