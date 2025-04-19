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
    datetime = db.Column(db.DateTime, default=lambda: datetime.now(UTC))


class KillSwitch(db.Model):
    __tablename__ = 'killswitch'
    id = db.Column(db.Integer, primary_key=True)
    round_1 = db.Column(db.Boolean, default=False)
    round_2 = db.Column(db.Boolean, default=False)
    round_3 = db.Column(db.Boolean, default=False)
