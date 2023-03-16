from tarfile import RECORDSIZE
from flask import Flask, render_template, request, url_for, redirect, session
from pymongo import MongoClient
from flask.json import jsonify
import bcrypt
#set app as a Flask instance p
app = Flask(__name__)
#encryption relies on secret keys so they could be run
app.secret_key = "testing"

# #connect to your Mongo DB database
def MongoDB():
    client = MongoClient("mongodb+srv://thando:Password01@thando.ykhkcig.mongodb.net/?retryWrites=true&w=majority")
    db = client.get_database('total_records')
    records = db.register
   

    db = client.users
    db = client.issues

    email_found = records.find_one({"email": "test@yahoo.com"})
    if not email_found:
        pw = "test123"
        hashed = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())
        records.insert_one({
            "name": "Test Test",
            "email": "test@yahoo.com",
            "password": hashed
        })
   
    return records

records = MongoDB()
    







##Connect with Docker Image###
#def dockerMongoDB():
    #client = MongoClient(host='test_mongodb',
        #                   port=27017, 
       #                     username='root', 
      #                     password='pass',
     #                      authSource="admin")
    #db = client.users
    #pw = "test123"
    #hashed = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())
    #records = db.register
    #records.insert_one({
      #  "name": "Test Test",
     #   "email": "test@yahoo.com",
    #    "password": hashed
  #  })
   # return records

#records = dockerMongoDB()


#assign URLs to have a particular route 
@app.route("/", methods=['POST', 'GET'])
def index():
    message = ''

    #if method post in index
    #if "email" in session:
       # return redirect(url_for("index"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        #if found in database showcase that it's found 
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('signup.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('signup.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('signup.html', message=message)
        else:
            #hash the password and encode it
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            #assing them in a dictionary in key value pairs
            user_input = {'name': user, 'email': email, 'password': hashed}
            #insert it in the record collection
            records.insert_one(user_input)
            
            #find the new created account and its email
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
            #if registered redirect to logged in as the registered user
            return render_template('user/dashboard.html', email=new_email)
    return render_template('index.html')

@app.route("/user/signup", methods=['POST', 'GET'])
def signup():
    message = ''
    #if method post in index
    #if "email" in session:
     #   return redirect(url_for("dashboard"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        #if found in database showcase that it's found 
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('user/signup.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('user/signup.html', message=message)
        if password2 != password1:
            message = 'Passwords should match!'
            return render_template('user/signup.html', message=message)
        else:
            #hash the password and encode it
            hashed = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
            #assing them in a dictionary in key value pairs
            user_input = {'name': user, 'email': email, 'password1': hashed}
            #insert it in the record collection
            records.insert_one(user_input)
            
            #find the new created account and its email
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
            #if registered redirect to logged in as the registered user
            return render_template('user/dashboard.html', email=new_email)
    return render_template('user/dashboard.html')

@app.route("/user/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    #if "email" in session:
        #return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        #check if email exists in database
        email_found = records.find_one({"email": email})
        print("email",email_found)
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password1']
            #encode the password and check if it matches
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('dashboard'))
            else:
                if "email" in session:
                    return redirect(url_for("dashboard"))
                message = 'Wrong password'
                return render_template('user/login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('user/login.html', message=message)
    return render_template('user/login.html', message=message)

@app.route("/admin/login", methods=["POST", "GET"])
def admin_login():
    message = 'Please login to your account'
    #if "email" in session:
        #return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        #check if email exists in database
        email_found = records.find_one({"email": email})

        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']
            #encode the password and check if it matches
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('admin_dashboard'))
            else:
                if "email" in session:
                    return redirect(url_for("admin_dashboard"))
                message = 'Wrong password'
                return render_template('admin/login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('admin/login.html', message=message)
    return render_template('admin/login.html', message=message)

@app.route('/dashboard')
def dashboard():
    if "email" in session:
        users = session["email"]
        print("USERS",users)
        return render_template('user/dashboard.html', users=users)
    else:
        return redirect(url_for("login"))

@app.route('/admin/dashboard')
def admin_dashboard():
    if "email" in session:
        users = session["email"]
        print("USERS",users)
        return render_template('admin/dashboard.html', users=users)
    else:
        return redirect(url_for("admin_login"))

@app.route("/logout", methods=["POST","GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return redirect(url_for("login"))
    else:
        return redirect(url_for("index"))


@app.route('/admin/all-user')
def lists():
    print("DATA",[i for i in records.find({})])
    users = [i for i in records.find({})]
    return render_template('admin/all-user.html', users=users)
    
@app.route("/user/file-report", methods=['POST', 'GET'])
def report():
    message = ''
    #if method post in index
    if "email" in session and request.method == "GET":
       return render_template('user/file-report.html')
    
    if request.method == "POST":
        campus = request.form.get("campus")
        block = request.form.get("block")
        description = request.form.get("description")
        date = request.form.get("date")
        #if found in database showcase that it's found 

        user_input = {'campus': campus, 'block': block, 'description': description, 'date': date}
            #insert it in the record collection
        records.insert_one(user_input)
           
            #if registered redirect to logged in as the registered user
        return redirect(url_for("dashboard"))


if __name__ == "__main__":
  app.run(debug=True, host='0.0.0.0', port=5000)
