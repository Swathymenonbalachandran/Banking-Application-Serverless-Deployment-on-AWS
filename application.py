from decimal import Decimal
import json, uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import requests, secrets
from flask_migrate import Migrate
from flask_cors import cross_origin
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFProtect

application = Flask(__name__)
application.config['SECRET_KEY'] = secrets.token_hex(16)
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Use your preferred database URL
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking, as it's not needed
db = SQLAlchemy(application)
bcrypt = Bcrypt(application)
migrate = Migrate(application, db)
csrf = CSRFProtect(application)

# API endpoint URL
API_ENDPOINT = "https://v4gp08sg4f.execute-api.eu-west-1.amazonaws.com/x23108568bankaccount"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)  # Add the new account number field
    contact = db.Column(db.String(20), unique=True, nullable=False)  # Add the new phone number field

    def __repr__(self):
        return f'<User {self.username}>'

class Deposit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), nullable=False)
    account_holder = db.Column(db.String(80), nullable=False)
    deposit_amount = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'<Deposit {self.account_number} - {self.deposit_amount}>'



@application.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        account_number = request.form['account_number']  # Get the new account number field
        contact = request.form['contact']  # Get the new phone number field

        # Add these fields to your User record in the database
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, account_number=account_number, contact=contact)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('signin'))

    return render_template('signup.html')


@application.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first() 
        if user and bcrypt.check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            session['username'] = username  # Store username in the session
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('signin.html')

@application.route('/signout')
def signout():
    # Clear the username from the session
    session.pop('username', None)
    flash('You have been signed out successfully!', 'success')
    return redirect(url_for('index'))


@application.route('/')
def index():
    username = session.get('username', None)
    return render_template('index.html', username=username)

@application.route('/addopennewaccount', methods=['POST', 'GET'])
def addopennewaccount():
    if request.method == 'POST':
        # Retrieve product details from the form
        account_holder = request.form['account_holder']
        account_type = request.form['account_type']
        address = request.form['address']
        contact = request.form['contact']
        currentbalance = request.form['currentbalance']
        initial_balance = request.form['initial_balance']
        passport_number = request.form['passport_number']

        try:
            # Generate a unique account number
            account_number = generate_unique_account_number()

            # Construct the payload as a dictionary
            payload = {
                'action': 'addopennewaccount',
                'userid': str(uuid.uuid4()),  # Generate a unique material_id, you can use your own logic here
                'account_holder': account_holder,
                'account_number': account_number,
                'account_type': account_type,
                'address': address,
                'contact': contact,
                'currentbalance': currentbalance,
                'initial_balance': initial_balance,
                'passport_number': passport_number,
            }

            # Send the payload as JSON data
            response = requests.post(API_ENDPOINT, json=payload)

            flash('New account added successfully!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            print(f'Error placing order from cart: {str(e)}')
            return render_template('error.html', error=f'Error placing order from cart: {str(e)}')
    elif request.method == 'GET':
        return render_template('addopennewaccount.html')
    
def generate_unique_account_number():
    while True:
        account_number = secrets.token_hex(6).upper()  # Adjust the length as needed
        if not User.query.filter_by(account_number=account_number).first():
            return account_number

@application.route('/addloan', methods=['POST', 'GET'])
@cross_origin()
@csrf.exempt
def addloan():
    if request.method == 'POST':
        # Retrieve loan details from the form
        loantype = request.form['loantype']
        loanpurpose = request.form['loanpurpose']
        loanamount = request.form['loanamount']
        employcategory = request.form['employcategory']
        moredetails = request.form['moredetails']
        idproof = request.form['idproof']
        passportimage = request.files.get('passportimage')  # New field
        if passportimage:
                print('Found passport_image')
                passportimage_data = passportimage.read()
                passportimage_base64 = base64.b64encode(passportimage_data).decode('utf-8')
                print('Base64 Encoded Image:', passportimage_base64)
        try:
            # Construct the payload as a dictionary
            payload = {
                'action': 'addloans',
                'loanid': str(uuid.uuid4()),  # Generate a unique loanid, you can use your own logic here
                'loantype': loantype,
                'loanpurpose': loanpurpose,
                'loanamount': loanamount,
                'employcategory': employcategory,
                'moredetails': moredetails,
                'idproof': idproof,  # Include the new field in the payload
                'passportimage': passportimage_base64
            }

            # Send the payload as JSON data
            response = requests.post(API_ENDPOINT, json=payload)

            flash('Loan added successfully!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            print(f'Error adding loan: {str(e)}')
            return render_template('error.html', error=f'Error adding loan: {str(e)}')
    elif request.method == 'GET':
        return render_template('addloan.html')

@application.route('/showuseraccounts')
def showuseraccounts():
    try:
        response = requests.get(API_ENDPOINT, json={'action': 'listaccounts'})
        if response.status_code == 200:
            # Parse the JSON response
            accounts = response.json()
            return render_template('showuseraccounts.html', accounts=accounts)
        else:
            return "Error fetching data from the API"
       
    except Exception as e:
        return f"Error: {str(e)}"
    
@application.route('/showallloans')
def showallloans():
    try:
        # Retrieve loan details from the DynamoDB or API
        response = requests.get(API_ENDPOINT, json={'action': 'getloans'})
        
        if response.status_code == 200:
            # Parse the JSON response
            loans = response.json()
            return render_template('showallloans.html', loans=loans)
        else:
            return "Error fetching loan data from the API"
       
    except Exception as e:
        return f"Error: {str(e)}"    

@application.route('/showaccounttypes')
def show_account_types():
    return render_template('showaccounttypes.html')


@application.route('/updateaccount', methods=['GET', 'POST'])
def updateaccount():
    # Retrieve product details from the form
    userid = request.form['userid']
    account_holder = request.form['account_holder']
    account_number = request.form['account_number']
    account_type = request.form['account_type']
    address = request.form['address']
    contact = request.form['contact']
    currentbalance = request.form['currentbalance']
    initial_balance = request.form['initial_balance']
    passport_number = request.form['passport_number']
    
 
    try:
        # Invoke the Lambda function to update the product in DynamoDB
        payload = {
            'action': 'updateaccount',
            'userid': userid,
            'account_number': account_number,
            'account_holder': account_holder,
            'account_type': account_type,
            'address': address,
            'contact': contact,
            'currentbalance': currentbalance,
            'initial_balance': initial_balance,
            'passport_number': passport_number,
           
        }
        response = requests.post(API_ENDPOINT, json=payload)
        
 
        flash('Account updated successfully!', 'success')
        return redirect(url_for('index'))
 
    except Exception as e:
        print(f"Error updating Account: {str(e)}")
        return render_template('error.html', error=f"Error updating Account: {str(e)}")
    

@application.route('/update/<string:userid>', methods=['GET','POST'])
def accountdetails(userid):
    try:
        if request.method == 'GET':
            # Fetch the details of the specific account using the userid
            response = requests.get(API_ENDPOINT, json={'action': 'get_account', 'userid': userid})
 
            if response.status_code == 200:
                # Parse the JSON response
                account = response.json()
                return render_template('addopennewaccount.html', account=account)
            else:
                flash('Error fetching product details from the API', 'danger')
                return redirect(url_for('index'))
 
        elif request.method == 'POST':
            # Retrieve updated account details from the form
            userid = request.form['userid']
            account_holder = request.form['account_holder']
            account_number = request.form['account_number']
            account_type = request.form['account_type']
            address = request.form['address']
            contact = request.form['contact']
            currentbalance = request.form['currentbalance']
            initial_balance = request.form['initial_balance']
            passport_number = request.form['passport_number']
 
            # Invoke the Lambda function to update the product in DynamoDB
            payload = {
                'action': 'updateaccount',
                'userid': userid,
                'account_holder': account_holder,
                'account_number': account_number,
                'account_type': account_type,
                'address': address,
                'contact': contact,
                'currentbalance': currentbalance,
                'initial_balance': initial_balance,
                'passport_number': passport_number,
            }
            response = requests.post(API_ENDPOINT, json=payload)
 
            if response.status_code == 200:
                flash('Product updated successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Error updating product. Please try again.', 'danger')
                return redirect(url_for('addopennewaccount', userid=userid))
 
    except Exception as e:
        flash(f"Error: {str(e)}", 'danger')
        return redirect(url_for('index'))

# ...
@application.route('/depositamount', methods=['GET', 'POST'])
def depositamount():
    if request.method == 'POST':
        account_number = request.form['account_number']
        account_holder = request.form['account_holder']
        deposit_amount = request.form['deposit_amount']

        try:
            # Save deposit details to the database
            with application.application_context():
                new_deposit = Deposit(account_number=account_number, account_holder=account_holder, deposit_amount=deposit_amount)
                db.session.add(new_deposit)
                db.session.commit()

            # Update the current balance in DynamoDB
            update_current_balance_dynamodb(account_number, deposit_amount)

            flash('Deposit successful!', 'success')
            return redirect(url_for('showuseraccounts'))

        except Exception as e:
            print("Error:", str(e))
            flash('Error during deposit. Please try again.', 'danger')
            return redirect(url_for('showuseraccounts'))

    return render_template('depositamount.html')

# Function to update the current balance in DynamoDB
def update_current_balance_dynamodb(account_number, deposit_amount):
    try:
        # Fetch the current balance from DynamoDB
        response = requests.get(API_ENDPOINT, json={'action': 'get_accounts', 'account_number': account_number})

        if response.status_code == 200:
            account = response.json()
            current_balance = Decimal(account.get('currentbalance', '0'))

            # Calculate the new balance
            new_balance = current_balance + Decimal(deposit_amount)

            print('new_balance:',new_balance)

            # Update the current balance in DynamoDB
            updateaccount(
                account.get('userid', ''),
                account.get('account_holder', ''),
                account_number,
                account.get('account_type', ''),
                account.get('address', ''),
                account.get('contact', ''),
                str(new_balance),  # Convert to string for DynamoDB Decimal compatibility
                account.get('initial_balance', ''),
                account.get('passport_number', '')
            )
        else:
            print(f"Error fetching account details from API: {response.status_code}")

    except Exception as e:
        print(f"Error updating current balance in DynamoDB: {str(e)}")



@application.route('/showalldeposit')
def showalldeposit():
    try:
        # Retrieve deposit details from the database
        deposit_details = Deposit.query.all()
        return render_template('showalldeposit.html', deposit_details=deposit_details)

    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    application.run(debug=True)
