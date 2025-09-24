from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class VerificationRequest(db.Model):
    __tablename__ = 'verification_requests'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)  # UUID для отслеживания статуса
    rc = db.Column(db.String(32), unique=True, nullable=True)  # Request Code для подтверждения
    hash_value = db.Column(db.String(256), unique=True, nullable=False)  # Hash для первого этапа
    hash_two =db.Column(db.String(256), unique=True, nullable=True)
    mdata = db.Column(db.String(1000), unique=False, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, success, timeout
    expires_at = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.Integer, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)

    def __repr__(self):
        return f'<VerificationRequest {self.uuid} - {self.status}>'

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    balance = db.Column(db.Float, nullable=False, default=10.0)
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    telegram_id = db.Column(db.String(256), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f'<User {self.uuid} - {self.is_admin}>'

class Company(db.Model):
    __tablename__ = 'companies'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(256), nullable=False)
    api_token = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    def __repr__(self):
        return f'<Company {self.uuid} - {self.name}>'

class CompanyStaff(db.Model):
    __tablename__ = 'company_staff'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(256), nullable=False)
    staff_token = db.Column(db.String(256), nullable=False)
    mdata = db.Column(db.String(1000), unique=False, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)