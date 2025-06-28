from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from config import SETTINGS
from flask_migrate import Migrate
from datetime import date, timedelta
from sqlalchemy import func

app = Flask(__name__, instance_relative_config=True)
app.config.update(SETTINGS)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

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
        except Exception:
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


class Habit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    frequency = db.Column(db.String(50), nullable=False)   # 'daily' or 'weekly'
    goal = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.Date, nullable=False, default=date.today)
    current_streak = db.Column(db.Integer, nullable=False, default=0)
    longest_streak = db.Column(db.Integer, nullable=False, default=0)
    progresses = db.relationship('Progress', backref='habit', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Habit {self.name}>"

class Progress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    habit_id = db.Column(db.Integer, db.ForeignKey('habit.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    count = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (
        db.UniqueConstraint('habit_id', 'date', name='unique_daily_progress'),
     ) # for any given habit and date there can be at most one row

    def __repr__(self):
        return f"<Progress Habit:{self.habit_id} on {self.date} = {self.count}>"

def require_login():
    if 'user_id' not in session:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))

@app.route('/habits', methods=['GET', 'POST'])
def habits():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        name      = request.form['name']
        frequency = request.form['frequency']
        goal      = int(request.form['goal'])

        new_habit = Habit(
            user_id=user.id,
            name=name,
            frequency=frequency,
            goal=goal
        )
        db.session.add(new_habit)
        db.session.commit()

        flash(f"Habit «{name}» created!", 'success')
        return redirect(url_for('habits'))

    habits = Habit.query.filter_by(user_id=user.id).all()
    today = date.today()

    p_today = Progress.query.filter_by(date=today).all()
    done_today = {p.habit_id for p in p_today}
    progress_today = {p.habit_id: p.count for p in p_today}

    week_start = today - timedelta(days=today.weekday())
    weekly_progress = {}
    for h in habits:
        if h.frequency == 'weekly':
            total = db.session.query(
                func.coalesce(func.sum(Progress.count), 0)
            ).filter(
                Progress.habit_id == h.id,
                Progress.date >= week_start,
                Progress.date <= today
            ).scalar()
            weekly_progress[h.id] = total or 0
        else:
            weekly_progress[h.id] = progress_today.get(h.id, 0)

    return render_template(
        'habits.html',
        habits=habits,
        done_today=done_today,
        progress_today=progress_today,
        weekly_progress=weekly_progress,
        week_start=week_start
    )

@app.route('/habits/<int:habit_id>/edit', methods=['POST'])
def edit_habit(habit_id):
    habit = Habit.query.get_or_404(habit_id)
    if habit.user_id != session.get('user_id'):
        flash('Not authorized.', 'danger')
        return redirect(url_for('habits'))

    habit.name = request.form['name']
    habit.frequency = request.form['frequency']
    habit.goal = int(request.form['goal'])
    db.session.commit()
    flash('Habit updated.', 'success')
    return redirect(url_for('habits'))

@app.route('/habits/<int:habit_id>/delete', methods=['POST'])
def delete_habit(habit_id):
    habit = Habit.query.get_or_404(habit_id)
    if habit.user_id != session.get('user_id'):
        flash('Not authorized.', 'danger')
        return redirect(url_for('habits'))
    db.session.delete(habit)
    db.session.commit()
    flash('Habit deleted.', 'info')
    return redirect(url_for('habits'))

@app.route('/habits/<int:habit_id>/complete', methods=['POST'])
def complete_habit(habit_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    habit = Habit.query.get_or_404(habit_id)
    if habit.user_id != session.get('user_id'):
        flash('How did you get here?!', 'danger')
        return redirect(url_for('habits'))
    today = date.today()
    try:
        count = int(request.form.get('count', 0))
    except ValueError:
        flash('Write number.', 'warning')
        return redirect(url_for('habits'))

    progress = Progress.query.filter_by(habit_id=habit_id, date=today).first()
    if not progress:
        progress = Progress(habit_id=habit_id, date=today, count=count)
        db.session.add(progress)
    else:
        progress.count = count

    if habit.frequency == 'daily':
        if count >= habit.goal:
            yesterday = today - timedelta(days=1)
            prev = Progress.query.filter_by(habit_id=habit_id, date=yesterday).first()
            if prev and prev.count >= habit.goal:
                habit.current_streak += 1
            else:
                habit.current_streak = 1
            if habit.current_streak > habit.longest_streak:
                habit.longest_streak = habit.current_streak
        else:
            habit.current_streak = 0

    elif habit.frequency == 'weekly':
        week_start = today - timedelta(days=today.weekday())
        week_end   = week_start + timedelta(days=6)

        total_this = db.session.query(
            db.func.coalesce(db.func.sum(Progress.count), 0)
        ).filter(
            Progress.habit_id==habit_id,
            Progress.date>=week_start,
            Progress.date<=week_end
        ).scalar()

        if total_this >= habit.goal:
            prev_start = week_start - timedelta(days=7)
            prev_end   = week_start - timedelta(days=1)
            total_prev = db.session.query(
                db.func.coalesce(db.func.sum(Progress.count), 0)
            ).filter(
                Progress.habit_id==habit_id,
                Progress.date>=prev_start,
                Progress.date<=prev_end
            ).scalar()

            if total_prev >= habit.goal:
                habit.current_streak += 1
            else:
                habit.current_streak = 1

            if habit.current_streak > habit.longest_streak:
                habit.longest_streak = habit.current_streak
        else:
            habit.current_streak = 0

    db.session.commit()
    flash(f"Save: «{habit.name}» – {count} from {habit.goal}", 'success')
    return redirect(url_for('habits'))
@app.route('/habits/<int:habit_id>/progress_data')
def progress_data(habit_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    habit = Habit.query.filter_by(id=habit_id, user_id=session['user_id']).first_or_404()

    # last 30 days
    end = date.today()
    start = end - timedelta(days=29)
    # fetch daily counts
    entries = (Progress.query
               .filter(Progress.habit_id==habit_id,
                       Progress.date>=start,
                       Progress.date<=end)
               .order_by(Progress.date)
               .all())

    # map dates → counts
    data_map = { e.date.isoformat(): e.count for e in entries }
    labels = [(start + timedelta(days=i)).isoformat() for i in range(30)]
    data   = [ data_map.get(d, 0) for d in labels ]

    return jsonify({ 'labels': labels, 'data': data })

if __name__ == '__main__':
    db.create_all()
    app.run()
