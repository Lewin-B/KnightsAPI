from flask import Flask, request, jsonify, session
import pyodbc
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
import os
import openai
import uuid
load_dotenv()

#Populate app
app = Flask(__name__)
app.secret_key = os.getenv('secret_key')
bcrypt = Bcrypt(app)

#Initialize gpt-3.5 model
openai.organization = "org-KpGrl3BiV909x0l7SyL5MmPC"
openai.api_key = os.getenv("API_KEY")
openai.Model.list()

#SQL server information
server = os.getenv('server')
database = os.getenv('database')
username = os.getenv('username')
password = os.getenv('password')


# Create a connection string
conn_str = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}'

def create_connection():
    cxn = pyodbc.connect(conn_str)
    db = cxn.cursor()
    return db


@app.route('/chat', methods=['GET'])
def chat():
    try:
        # Connect to database
        case = session['caseid']
        db = create_connection()
        db.execute('SELECT * FROM cases where caseNumber = ?', case)
        data = db.fetchall()
        #Close connection
        db.close()

        #Create gpt Intro prompt
        introduction = 'You are now a legal assistant chatbot named Lawgic Bot assisting a client with the following case. Introduce yourself and what you do'
        messages = [
                {'role': 'system', 'content': introduction },
                {'role': 'user', 'content': str(data)}
        ]

        #Prompt GPT
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages,
            temperature=0,
            max_tokens=300
        )

        message = response['choices'][0]['message']['content']

        return jsonify({'message' : message})
    except Exception as e:
        print(e)
        return jsonify({'message' : 'Failed to register message', 'status': 'FAILED'})

    
@app.route('/prompt', methods=['POST'])
def prompt():
    try:
        data = request.json
        message = data['message']
        caseid = session['caseid']
        db = create_connection()
        db.execute('SELECT * FROM cases where caseNumber = ?', caseid)
        case = db.fetchall()

        #intialize gpt model
        introduction = 'You are now a legal assistant chatbot named Lawgic Bot assisting a client with the following case answer the following questions accordingly'
        messages = [
                {'role': 'system', 'content': introduction },
                {'role': 'user', 'content': str(case)},
                {'role': 'system', 'content': message },
        ]

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages,
            temperature=0,
            max_tokens=250
        )

        chat_message = response['choices'][0]['message']['content']
        print(chat_message)
        return jsonify({'message' : chat_message})
    except Exception as e:
        print(e)
        return jsonify({'message' : 'prompt not received succesfully'})

@app.route('/login', methods=['POST'])
def login():
    db = create_connection()
    db.execute('SELECT * FROM users')
    users = db.fetchall()
    try:
        data = request.json  # Access the JSON data sent in the request
        print("5")
        print(data['email'])
        print(data['password'])
        print(users[1][1])
        # Check if the provided email and password match any user in the database
        user = next((u for u in users if u[0] == data['email'] and bcrypt.check_password_hash(u[1], data['password'])), None)

        print(user)

        if user:
            db.execute('SELECT caseNumber FROM users WHERE email = ?', (data['email']))
            caseid = db.fetchall()
            print(caseid[0])
            # If user is found, set up a session to log them in
            if caseid:
                # If user is found, set up a session to log them in
                session['user_email'] = user[2]
                session['caseid'] = caseid[0][0]
                message = 'Login successful'
                return jsonify({'message': message, 'status': 'SUCCESS'})
            else:
                return jsonify({'message': 'No caseNumber found for this user', 'status': 'FAILED'})
        else:
            print('error')
            return jsonify({'message' : 'Login failed'})
    except Exception as e:
        print(e)
        return jsonify({'message' : 'Login failed'})

@app.route('/signup', methods=['POST'])
def signup():
    try:
        
        data = request.json
        db = create_connection()

        #Load in form data
        email = data['email']
        password = data['password']
        caseDate = data['caseDate']
        caseRepresentative = data['caseRepresentative']
        clientName = data['clientName']
        caseType = data['caseType']
        description = data['caseDescription']

        #Generate password Hash
        hashed_password = bcrypt.generate_password_hash(password)
        #Generate Case ID
        caseNumber = str(uuid.uuid1())

        # Input validation
        if not email or not password:
            return jsonify({'message': 'Email and password are required fields', 'status': 'FAILED'}), 400

        # Check if the email is already registered (optional)
        db.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = db.fetchone()
        if existing_user:
            print("existing user")
            return jsonify({'message': 'Email already registered', 'status': 'FAILED'}), 400
        #Insert values into database
        db.execute("INSERT INTO users (email, caseNumber, password) VALUES (?, ?, ? )",
                    (email, caseNumber, hashed_password,))
        db.commit()
        db.execute('INSERT INTO cases (CaseNumber, CaseDate, CaseRepresentative, ClientName, CaseType, CaseDescription) VALUES (?, ?, ?, ?, ?, ?)', 
                    (caseNumber, caseDate, caseRepresentative, clientName, caseType, description))
        db.commit()
        db.close()
        session['user_email'] = email
        session['caseid'] = caseNumber

        return ({'message': 'Sign Up Successful', 'status': 'SUCCESS'}), 200
    except Exception as e:
        print(e)
        return jsonify({'message' : 'Sign Up Unsuccessful'}), 400

@app.route('/logout')
def logout():
    #claer session data
    session.clear()

    return jsonify({'message' : 'session cleared', 'status': 'SUCCESS'})


if __name__ == '__main__':
    app.run(debug=True)



