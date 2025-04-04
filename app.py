from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from config import SETTINGS


app = Flask(__name__)
app.config.update(SETTINGS)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique user id
    username = db.Column(db.String(80), unique=True, nullable=False)  # Username
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email address
    password = db.Column(db.String(128), nullable=False)  # Hashed password

    def __repr__(self):
        return f"<User {self.username}>"
@app.route('/')
def index():
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            # In case of error (like duplicate username/email), roll back the session.
            db.session.rollback()
            flash('Error: Username or email may already exist.', 'danger')

    return render_template('index.html', form_type='register')

@app.route('/change_username', methods=['POST'])
def change_username():
    if 'user_id' not in session:
        flash('Your session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    new_username = request.form['new_username']

    # Check if username already exists
    if User.query.filter_by(username=new_username).first():
        flash('Username already in use. Try another.', 'warning')
    else:
        user.username = new_username
        try:
            db.session.commit()
            flash('Username updated successfully.', 'success')
        except Exception:
            db.session.rollback()
            flash('An error occurred while updating username.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        flash('Your session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    current_password = request.form['current_password']
    new_password = request.form['new_password']

    # Verify current password before updating
    if bcrypt.check_password_hash(user.password, current_password):
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        try:
            db.session.commit()
            flash('Password updated successfully.', 'success')
        except Exception:
            db.session.rollback()
            flash('An error occurred while updating password.', 'danger')
    else:
        flash('Current password is incorrect.', 'danger')

    return redirect(url_for('dashboard'))
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        flash('Your session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    try:
        db.session.delete(user)
        db.session.commit()
        session.pop('user_id', None)
        flash('Your account has been deleted successfully.', 'success')
        return redirect(url_for('register'))
    except Exception:
        db.session.rollback()
        flash('An error occurred during account deletion.', 'danger')
        return redirect(url_for('dashboard'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session.permanent = True
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your credentials.', 'danger')

    return render_template('index.html', form_type='login')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Your session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('index.html', form_type='dashboard', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    db.create_all()
    app.run()
