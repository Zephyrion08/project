from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
admin = Admin(app)
db = SQLAlchemy(app)

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(20), nullable=False, )
    password = db.Column(db.String(80), nullable=False)
    cpassword = db.Column(db.String(80), nullable=False)

admin.add_view(ModelView(User, db.session))

@app.route('/')
def login():
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

@app.route('/login_validation', methods=['POST'])
def login_validation():
    username = request.form.get('username')
    password = request.form.get('pass1')

    user = User.query.filter_by(username=username, password=password).first()

    if user:
        session['user_id'] = user.user_id
        session['username'] = user.username  # Store username in session
        return redirect('/home')
    else:
        return redirect('/')

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('pass2')
    cpassword = request.form.get('cpass2')

    new_user = User(username=username, email=email, password=password, cpassword=cpassword)
    db.session.add(new_user)
    db.session.commit()

    session['user_id'] = new_user.user_id

    return redirect('/home')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
