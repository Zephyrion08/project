from flask import Flask, render_template, request,redirect,session
import mysql.connector
import os


app = Flask(__name__)
app.secret_key=os.urandom(24)



conn=mysql.connector.connect(host="localhost",user="root",password="",database="database")
cursor = conn.cursor()



@app.route('/')
def login():  # put application's code here
    if 'user_id' in session:        
        return render_template('index.html')
    else:

        return render_template('login.html')

@app.route('/home')
def home():
    if 'user_id' in session:        
        return render_template('index.html')
    else:
        return redirect('/')



@app.route('/login_validation',methods=['POST'])
def login_validation():

    username = request.form.get('username')
    password = request.form.get('pass1')

    cursor.execute("""SELECT * FROM `user` WHERE `username` LIKE '{}' AND `password` LIKE '{}' """
                   .format(username,password))
    users=cursor.fetchall()

    if len(users)>0:
        session['user_id']=users[0][0]
        return redirect('/home')
    else:
        return redirect('/')


@app.route('/add_user',methods=['POST'])
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('pass2')
    cpassword = request.form.get('cpass2')

    cursor.execute("""INSERT INTO `user` (`user_id`,`username`,`email`,`password`,`cpassword`)  VALUES(NULL,'{}','{}','{}','{}')"""
                   .format(username,email,password,cpassword))
    conn.commit()

    cursor.execute("""SELECT * FROM `user` WHERE `username` LIKE '{}' AND `email` LIKE '{}' """.format(username,email))
    myuser=cursor.fetchall()
    session['user_id']=myuser[0][0]

    return redirect('/home')

@app.route('/logout')
def logout():
    session.pop('user_id')
    return redirect('/')



if __name__ == '__main__':
    app.run(debug=True)
