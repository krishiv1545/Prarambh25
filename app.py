from flask import Flask, render_template, request, redirect, url_for, session, flash
from models import db, User, KillSwitch, Round1_Questions, Round2_Questions, Scores
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, UTC
import os
from sqlalchemy.exc import IntegrityError


load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db.init_app(app)

with app.app_context():
    db.create_all()

    # Check if admin exists first
    admin_username = os.getenv('ADMIN_USERNAME')
    if not User.query.filter_by(username=admin_username).first():
        try:
            new_user = User(
                enrollmentno='231260107017',
                username=admin_username,
                password=generate_password_hash(os.getenv('ADMIN_PASSWORD')),
                role='admin',
                datetime=datetime.now(UTC)  # Fixed UTC reference
            )
            db.session.add(new_user)
            db.session.commit()
            print("Admin user created.")
        except IntegrityError:
            db.session.rollback()
            print("Admin user already exists")
    else:
        print("Admin user already exists")

    # Check if killswitch exists
    if not KillSwitch.query.first():
        try:
            new_killswitch = KillSwitch(
                round_1=False, round_2=False, round_3=False)
            db.session.add(new_killswitch)
            db.session.commit()
            print("Killswitch initialized.")
        except IntegrityError:
            db.session.rollback()
            print("Killswitch already exists")
    else:
        print("Killswitch already exists")


@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('signup.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        enrollmentno = request.form['enrollmentno']
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        try:
            new_user = User(enrollmentno=enrollmentno, username=username,
                            password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Username or email already exists.', 'error')
            print(e)
    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('home'))

    if session['role'] == 'admin':
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)
    elif session['role'] == 'participant':
        return render_template('dashboard.html')
    else:
        flash('Invalid role.', 'error')
        return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            if user.role == 'admin':
                flash('Welcome Admin!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Welcome Participant!', 'success')
                return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/round-1', methods=['GET', 'POST'])
def round_1():
    if 'user_id' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('home'))

    status = KillSwitch.query.first()
    if status.round_1 == True:
        return render_template('round_1.html')
    else:
        flash('Round 1 is not active.', 'error')
        return redirect(url_for('dashboard'))

    return redirect(url_for('dashboard'))


@app.route('/admin-dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('home'))

    round1_questions = Round1_Questions.query.all()
    round2_questions = Round2_Questions.query.all()

    return render_template('admin_dashboard.html',
                           round1_questions=round1_questions,
                           round2_questions=round2_questions)


@app.route('/delete-round1-question/<int:question_id>', methods=['GET'])
def delete_round1_question(question_id):
    question = Round1_Questions.query.get(question_id)
    if question:
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully.', 'success')
    else:
        flash('Question not found.', 'error')
    return redirect(url_for('admin_dashboard'))


@app.route('/delete-round2-question/<int:question_id>', methods=['GET'])
def delete_round2_question(question_id):
    question = Round2_Questions.query.get(question_id)
    if question:
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully.', 'success')
    else:
        flash('Question not found.', 'error')
    return redirect(url_for('admin_dashboard'))


@app.route('/add-round1-question', methods=['POST'])
def add_round1_question():

    if request.method == 'POST':
        question = request.form['question']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        answer = request.form['answer']

        new_question = Round1_Questions(question=question, option1=option1,
                                        option2=option2, option3=option3, option4=option4, answer=answer)
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/add-round2-question', methods=['POST'])
def add_round2_question():

    if request.method == 'POST':
        question = request.form['question']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        answer = request.form['answer']

        new_question = Round2_Questions(question=question, option1=option1,
                                        option2=option2, option3=option3, option4=option4, answer=answer)
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)
