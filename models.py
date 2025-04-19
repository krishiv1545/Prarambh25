from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, UTC

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    enrollmentno = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default='participant')
    preferred_language = db.Column(db.String(50))
    datetime = db.Column(db.DateTime, default=lambda: datetime.now(UTC))


class KillSwitch(db.Model):
    __tablename__ = 'killswitch'
    id = db.Column(db.Integer, primary_key=True)
    round_1 = db.Column(db.Boolean, default=False)
    round_2 = db.Column(db.Boolean, default=False)
    round_3 = db.Column(db.Boolean, default=False)


class Round1_Questions(db.Model):
    __tablename__ = 'round1_questions'
    id = db.Column(db.Integer, primary_key=True)

    python_question = db.Column(db.String(1024), nullable=False)
    c_question = db.Column(db.String(1024), nullable=False)

    option1 = db.Column(db.String(256), nullable=False)
    option2 = db.Column(db.String(256), nullable=False)
    option3 = db.Column(db.String(256), nullable=False)
    option4 = db.Column(db.String(256), nullable=False)
    answer = db.Column(db.Integer, nullable=False)


class Round2_Questions(db.Model):
    __tablename__ = 'round2_questions'
    id = db.Column(db.Integer, primary_key=True)

    python_question = db.Column(db.String(1024), nullable=False)
    c_question = db.Column(db.String(1024), nullable=False)

    option1 = db.Column(db.String(256), nullable=False)
    option2 = db.Column(db.String(256), nullable=False)
    option3 = db.Column(db.String(256), nullable=False)
    option4 = db.Column(db.String(256), nullable=False)
    answer = db.Column(db.Integer, nullable=False)


class Scores(db.Model):
    __tablename__ = 'scores'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    round_1_score = db.Column(db.Integer, nullable=False)
    round_2_score = db.Column(db.Integer, nullable=False)
