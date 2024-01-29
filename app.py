from flask import Flask, render_template, request, redirect, session, flash, url_for,abort
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re
import requests
from MySQLdb import IntegrityError

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')

db = SQLAlchemy(app)

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    cpassword = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class WatchlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    movie_title = db.Column(db.String(255), nullable=False)
    movie_poster_url = db.Column(db.String(255), nullable=False)
    movie_description = db.Column(db.Text, nullable=False)

class CustomModelView(ModelView):
    def is_accessible(self):
        return 'user_id' in session and session['user_id'] == 1

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

class CustomAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return 'user_id' in session and session['user_id'] == 1

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

admin = Admin(app, index_view=CustomAdminIndexView())
admin.add_view(CustomModelView(User, db.session))
admin.add_view(CustomModelView(WatchlistItem, db.session))

@app.route('/')
def login():
    if 'user_id' in session:
        return render_template('index.html')
    else:
        return render_template('login.html')

@app.route('/index')
def index():
    if 'user_id' in session:
        return render_template('index.html')
    else:
        return redirect('/')

@app.route('/home')
def home():
    if 'user_id' in session:
        return render_template('home.html')
    else:
        return redirect('/')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    watchlist = WatchlistItem.query.filter_by(user_id=session['user_id']).all()

    return render_template('profile.html', user=user, watchlist=watchlist)

@app.route('/login_validation', methods=['POST'])
def login_validation():
    username = request.form.get('username')
    password = request.form.get('pass1')

    is_email = '@' in username

    if is_email:
        user = User.query.filter_by(email=username).first()
    else:
        user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session['user_id'] = user.user_id
        session['username'] = user.username
        return redirect('/index')
    else:
        flash('Invalid username or password', 'error')
        return redirect('/')

def is_valid_password(password):
    if (
        len(password) < 8
        or not re.search(r'[A-Z]', password)
        or not re.search(r'[a-z]', password)
        or not re.search(r'\d', password)
        or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    ):
        return False
    return True

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('pass2')
    cpassword = request.form.get('cpass2')

    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        flash('Username or email already exists', 'error')
        return redirect('/')

    if not is_valid_password(password):
        flash('Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.', 'error')
        return redirect('/')

    if password != cpassword:
        flash('Passwords do not match', 'error')
        return redirect('/')

    hashed_password = generate_password_hash(password)

    new_user = User(username=username, email=email, password=hashed_password, cpassword=cpassword)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.user_id
        return redirect('/home')
    except IntegrityError:
        db.session.rollback()
        flash('Error adding user to the database', 'error')
        return redirect('/')

@app.route('/movie_info/<movie_title>')
def movie_info(movie_title):

    TMDB_API_KEY = '9908d5c57aa75311ed218356b6ed4058'
    search_url = f'https://api.themoviedb.org/3/search/movie'
    search_params = {'api_key': TMDB_API_KEY, 'query': movie_title}

    search_response = requests.get(search_url, params=search_params)
    search_results = search_response.json()

    if search_results['results']:
        movie_id = search_results['results'][0]['id']
        movie_url = f'https://api.themoviedb.org/3/movie/{movie_id}'
        movie_params = {'api_key': TMDB_API_KEY}

        movie_response = requests.get(movie_url, params=movie_params)
        movie_data = movie_response.json()

        return render_template('movie_info.html', movies=movie_data)
    else:
        abort(404)

@app.route('/add_to_watchlist/<movie_title>', methods=['POST'])
def add_to_watchlist(movie_title):
    if 'user_id' not in session:
        flash('You must be logged in to add movies to your watchlist.', 'error')
        return redirect(url_for('login'))

    existing_watchlist_item = WatchlistItem.query.filter_by(user_id=session['user_id'], movie_title=movie_title).first()
    if existing_watchlist_item:
        flash('This movie is already in your watchlist.', 'error')
    else:
        movie_poster_url = request.form.get('movie_poster_url')
        movie_description = request.form.get('movie_description')

        new_watchlist_item = WatchlistItem(
            user_id=session['user_id'],
            movie_title=movie_title,
            movie_poster_url=movie_poster_url,
            movie_description=movie_description
        )
        db.session.add(new_watchlist_item)
        db.session.commit()
        flash('Movie added to your watchlist successfully.', 'success')

    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
