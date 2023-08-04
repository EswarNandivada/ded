from flask import Flask, request, redirect, render_template, url_for, flash,session,abort,jsonify
import flask_excel as excel
from flask_session import Session
import mysql.connector
import random
from io import BytesIO
from key import secret_key, salt, salt2
from itsdangerous import URLSafeTimedSerializer
from stoken import token,token2
from cmail import sendmail
import os
import uuid
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
import stripe
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

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
     cursor.execute("CREATE TABLE if not exists register (ID int NOT NULL AUTO_INCREMENT,FirstName varchar(25) DEFAULT NULL,LastName varchar(25) DEFAULT NULL,Email varchar(50) DEFAULT NULL,PASSWORD longblob,mobileno bigint DEFAULT NULL,age int DEFAULT NULL,gender varchar(10) DEFAULT NULL,DOB date DEFAULT NULL,city text,address text,state text,country text,degree varchar(10) DEFAULT NULL,MCI_ID varchar(20) DEFAULT NULL,member varchar(20) DEFAULT NULL,SHIRT_SIZE enum('S','M','L','XL','XXL','XXXL','XXXXL') DEFAULT NULL,acception varchar(30) DEFAULT 'No',status varchar(20) NOT NULL DEFAULT 'pending',PRIMARY KEY (ID),UNIQUE KEY Email (Email),UNIQUE KEY mobileno (mobileno))")
     cursor.execute("CREATE TABLE if not exists game (ID INT, game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),AMOUNT INT UNSIGNED)")
     cursor.execute("create table if not exists games(game_name varchar(30),amount int unsigned,team_count int)")
     cursor.execute("insert into games values('ATHLETICS',1500,1),('ARCHERY',1500,1),('BADMINTON',1500,2),('BASKETBALL',10000,9),('BALL BADMINTON',10000,7),('CARROMS',1500,2),('CHESS',1500,1),('CYCLOTHON',1500,1),('JUMPS',1500,1),('SWIMMING',1500,1),('THROW',1500,1),('ROWING',1500,1),('SHOOTING',1500,1),('ROLLER SKATING',1500,1),('FENCING',1500,1),('TENNIKOIT',1500,1),('TABLE TENNIS',1500,2),('LAWN TENNIS',1500,2),('CRICKET WHITE BALL',30000,14),('HARD TENNIS CRICKET',20000,14),('WOMEN BOX CRICKET',10000,7),('VOLLEY BALL',10000,9),('FOOTBALL',10000,11),('KHO KHO',10000,12),('KABADDI',10000,10),('THROWBALL',10000,10),('TUG OF WAR',5000,10)")
     cursor.execute("create table if not exists payments(ordid varchar(36),id int,game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),amount int unsigned,date timestamp default now() on update now(),foreign key(id) references register(id))")
     cursor.execute("CREATE TABLE if not exists sub_games (game enum('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'),id int ,category varchar(50),team_number int unique, date timestamp default current_timestamp on update current_timestamp,foreign key(id) references register(id))")
     cursor.execute("create table if not exists teams(teamid int,id int,status enum('Accept','Pending'),foreign key(teamid) references sub_games(team_number),foreign key(id) references register(id))")
     cursor.close()
mydb=mysql.connector.connect(host=host,user=user,password=password,db=db,pool_name='DED',pool_size=30)

stripe.api_key='sk_test_51NTKipSDmVNK7hRpj4DLpymMTojbp0sntuHknEF9Kv3cGY79VkNbmBcfxDmTLXa9UIGKiiqp8drQQhzsjoia58Sm00Kuzg9vYt'

# Configure the upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/certificates')
app.config['UPLOAD_FOLDERS'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/photos')
app.config['UPLOAD_FOLDERSS'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads/dob')


bcrypt = Bcrypt(app)



class Eazypay:
    def __init__(self):
        self.merchant_id = '600541'
        self.encryption_key = b'6000012605405020'
        self.sub_merchant_id = '45'
        self.paymode = '9'
        self.return_url = 'https://doctorsolympiad.com/purchase-summary/order-received/doctors'

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
            f"https://eazypayuat.icicibank.com/EazyPG?merchantid={self.merchant_id}"
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
    return render_template('refund-schedule.html')




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


@app.route('/payment/<eid>/<game>', methods=['GET', 'POST'])
def payment(eid,game):
    cursor = mydb.cursor(buffered=True)
    cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo, member FROM register WHERE id=%s", [eid])
    data1 = cursor.fetchall()
    cursor.execute('SELECT status from register WHERE id=%s', [eid])
    status=cursor.fetchone()[0]
    if status=='pending':
        cursor.execute("SELECT game, amount FROM game WHERE id=%s", [eid])
        cursor.close()
        game,amount = cursor.fetchone()
    else:
        cursor.execute('select amount from games where game_name=%s',[game])
        amount=cursor.fetchone()[0]
        cursor.close()
    ref=uuid.uuid4()
    return render_template('payment.html', data1=data1,game=game,amount=amount,eid=eid,ref=ref)


@app.route('/pay/<eid>/<game>/<ref>',methods=['POST'])
def pay(eid,game,ref):
    cursor = mydb.cursor(buffered=True)
    cursor.execute('SELECT status from register WHERE id=%s', [eid])
    status=cursor.fetchone()[0]
    if status=='pending':
        cursor.execute('SELECT amount FROM game WHERE id=%s', [eid])
        amount = cursor.fetchone()[0]
        cursor.close()
    else:
        cursor.execute('select amount from games where game_name=%s',[game])
        amount=cursor.fetchone()[0]
        #q=int(request.form['qty'])
    q = 1
    checkout_session=stripe.checkout.Session.create(
        success_url=url_for('success',eid=eid,game=game,amount=amount,ref=ref,_external=True),
        line_items=[
            {
                'price_data': {
                    'product_data': {
                        'name': game,
                    },
                    'unit_amount': amount*100,
                    'currency': 'inr',
                },
                'quantity':q
            },
            ],
        mode="payment",)
    return redirect(checkout_session.url)
@app.route('/success/<eid>/<ref>/<game>/<amount>')
def success(eid,ref,game,amount):
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
        cursor.execute("select mobileno from register where id =%s",[eid])
        mobile=cursor.fetchone()[0]
        cursor.close()
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
        return redirect(url_for('individual'))
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
        cursor.execute('''SELECT status from teams as t inner join sub_games as s on t.teamid=s.team_number where t.game=%s''',[game])
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
        cursor=mydb.cursor(buffered=True)
        cursor.execute("SELECT count(*) from sub_games where id=%s and game=%s",[session.get('user'),game])
        count=cursor.fetchone()[0]
        if count==0:
            if request.method=='POST':
                for i in request.form:
                    if request.form[i] in ("Id not found","User Registered to other team" ,'User already Registered in other cricket team','You cannot add yourself.','User already Registered in two teams'):
                        return jsonify({'message':request.form[i]})
                else:
                    return jsonify({'message':'Success'})
            return render_template(f'/games-individual-team/Team/{game}.html',gender=gender,game=game,count=count)
        else:
            pass


@app.route('/update/<game>', methods=['POST'])
def update(game):
    if session.get('user'):
        input_value = request.form['inputValue']
        # Here, you can perform any necessary processing with the input data.
        # For simplicity, we'll just return the input value as the response.
        if input_value.isdigit():
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from register where id=%s',[input_value])
            data=cursor.fetchone()[0]
            cursor.close()
            if data==0:
                message="Id not found"
            elif int(data)==session.get('user'):
                message='You cannot add yourself.'
            else:
                cond=True
                cursor=mydb.cursor(buffered=True)
                cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[input_value,game,'Accept'])
                count=cursor.fetchone()[0]
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
                    cond=False
                    message='User already Registered in other cricket team'
                if cond==True and  message!="You cannot add yourself.":
                    cursor.execute("SELECT concat_ws(" ",FirstName,LastName) as fullname from register where id=%s",[input_value])
                    message=cursor.fetchone()[0]
                cursor.close()
            
        else:
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from register where email=%s',[input_value])
            data=cursor.fetchone()[0]
            cursor.close()
            if data==0:
                message="User not found with this email id"
            else:
                cond=True
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id from register where Email=%s',[input_value])
                eid=cursor.fetchone()[0]
                cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[eid,game,'Accept'])
                count=cursor.fetchone()[0]
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
                    cond=False
                    message='User already Registered in other cricket team'
                if cond==True and message!='You cannot add yourself.':
                    cursor.execute("SELECT concat_ws(' ',FirstName,LastName) as fullname from register where id=%s",[eid])
                    message=cursor.fetchone()[0]
                cursor.close()
        response = {'outputValue': message}
        return jsonify(response)
    else:
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()
