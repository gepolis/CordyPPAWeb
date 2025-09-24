import base64
import hashlib
import io
import random
import string
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps

import jwt
from Crypto.Util.Padding import unpad
from flask import Flask, request, jsonify, render_template, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import qrcode
from flask import Response
from db import db, VerificationRequest, User, Company, CompanyStaff
from pkcs5 import AES_pkcs5
from werkzeug.security import generate_password_hash, check_password_hash

chars = string.ascii_letters + string.digits
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///verification.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

db.init_app(app)

reqs = {}
codes = {}


def generate_hash():
    return ''.join(random.choice(chars) for _ in range(128))


SALT = "KSuLR90dYl1Ntfq6gJYa7jSsgGRtO8ODrpoxd0NNBCcPPzFu3fTj6lC32ezTg7BJP"


# JWT токен декоратор для защиты маршрутов
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Убираем 'Bearer ' из токена
            if token.startswith('Bearer '):
                token = token[7:]

            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(uuid=data['user_uuid']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


def company_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Убираем 'Bearer ' из токена
            if token.startswith('Bearer '):
                token = token[7:]

            # Ищем компанию по api_token
            company = Company.query.filter_by(api_token=token).first()
            if not company:
                return jsonify({'message': 'Invalid company token!'}), 401

        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(company, *args, **kwargs)

    return decorated
# API для регистрации
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required!'}), 400

    # Проверяем, существует ли пользователь
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User already exists!'}), 400

    # Создаем нового пользователя
    hashed_password = generate_password_hash(data['password'])
    user_uuid = str(uuid.uuid4())

    # Генерируем случайный telegram_id (в реальном приложении это будет привязка к Telegram)
    telegram_id = str(random.randint(100000000, 999999999))

    new_user = User(
        uuid=user_uuid,
        email=data['email'],
        password=hashed_password,
        telegram_id=telegram_id
    )

    try:
        db.session.add(new_user)
        db.session.commit()

        # Генерируем JWT токен
        token = jwt.encode({
            'user_uuid': user_uuid,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        print(token)
        return jsonify({
            'message': 'User created successfully!',
            'token': token,
            'user': {
                'uuid': user_uuid,
                'email': data['email']
            }
        }), 201
    except Exception as e:
        return jsonify({'message': 'Error creating user!'}), 500


# API для входа
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials!'}), 401

    # Генерируем JWT токен
    token = jwt.encode({
        'user_uuid': user.uuid,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    print(token)
    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'user': {
            'uuid': user.uuid,
            'email': user.email,
            'balance': user.balance,
            'is_admin': user.is_admin
        }
    })


# API для создания компании
@app.route('/api/company/create', methods=['POST'])
@token_required
def create_company(current_user):
    data = request.get_json()

    if not data or not data.get('name'):
        return jsonify({'message': 'Company name is required!'}), 400

    # Создаем новую компанию
    company_uuid = str(uuid.uuid4())
    api_token = generate_hash()[:64]
    public_key = generate_hash()[:64]

    new_company = Company(
        uuid=company_uuid,
        name=data['name'],
        api_token=api_token,
        public_key=public_key,
        created_at=int(time.time()),
        user_id=current_user.id
    )

    try:
        db.session.add(new_company)
        db.session.commit()

        return jsonify({
            'message': 'Company created successfully!',
            'company': {
                'uuid': company_uuid,
                'name': data['name'],
                'api_token': api_token,
                'public_key': public_key
            }
        }), 201
    except Exception as e:
        return jsonify({'message': 'Error creating company!'}), 500


# API для получения списка компаний пользователя
@app.route('/api/companies', methods=['GET'])
@token_required
def get_companies(current_user):
    companies = Company.query.filter_by(user_id=current_user.id).all()

    companies_list = []
    for company in companies:
        companies_list.append({
            'uuid': company.uuid,
            'name': company.name,
            'api_token': company.api_token,
            'public_key': company.public_key,
            'created_at': company.created_at
        })

    return jsonify({'companies': companies_list})


# API для добавления сотрудника в компанию
@app.route('/api/company/<company_uuid>/staff', methods=['POST'])
@token_required
def add_staff(current_user, company_uuid):
    data = request.get_json()

    if not data or not data.get('name') or not data.get('mdata'):
        return jsonify({'message': 'Name and metadata are required!'}), 400

    # Проверяем, что компания принадлежит пользователю
    company = Company.query.filter_by(uuid=company_uuid, user_id=current_user.id).first()
    if not company:
        return jsonify({'message': 'Company not found!'}), 404

    # Создаем нового сотрудника
    staff_uuid = str(uuid.uuid4())
    staff_token = generate_hash()[:32]

    new_staff = CompanyStaff(
        uuid=staff_uuid,
        name=data['name'],
        staff_token=staff_token,
        mdata=data['mdata'],
        company_id=company.id
    )

    try:
        db.session.add(new_staff)
        db.session.commit()

        return jsonify({
            'message': 'Staff added successfully!',
            'staff': {
                'uuid': staff_uuid,
                'name': data['name'],
                'staff_token': staff_token
            }
        }), 201
    except Exception as e:
        return jsonify({'message': 'Error adding staff!'}), 500


# API для получения списка сотрудников компании
@app.route('/api/company/<company_uuid>/staff', methods=['GET'])
@token_required
def get_staff(current_user, company_uuid):
    # Проверяем, что компания принадлежит пользователю
    company = Company.query.filter_by(uuid=company_uuid, user_id=current_user.id).first()
    if not company:
        return jsonify({'message': 'Company not found!'}), 404

    staff_list = CompanyStaff.query.filter_by(company_id=company.id).all()

    staff_data = []
    for staff in staff_list:
        staff_data.append({
            'uuid': staff.uuid,
            'name': staff.name,
            'staff_token': staff.staff_token,
            'mdata': staff.mdata
        })

    return jsonify({'staff': staff_data})


# API для генерации QR верификации
@app.route('/api/company/<company_uuid>/qr_verify', methods=['GET'])
@token_required
def generate_verify_qr(current_user, company_uuid):
    # Проверяем, что компания принадлежит пользователю
    company = Company.query.filter_by(uuid=company_uuid, user_id=current_user.id).first()
    if not company:
        return jsonify({'message': 'Company not found!'}), 404

    # Создаем запрос верификации
    lifetime = request.args.get('lifetime', 60, type=int)
    mdata = request.args.get('mdata', '')

    h0 = generate_hash()
    h1 = generate_hash()
    rch = generate_hash()
    uuid_g = uuid.uuid4()
    cr_at = int(time.time())
    expires_at = cr_at + lifetime

    vr = VerificationRequest(
        uuid=str(uuid_g),
        created_at=cr_at,
        expires_at=expires_at,
        mdata=mdata,
        hash_value=h0,
        hash_two=h1,
        rc=rch
    )

    db.session.add(vr)
    db.session.commit()

    # Создаем QR-код с hash_value
    qr = qrcode.make(
        version=1,
        box_size=10,
        border=4,
        data=h0
    )

    # Сохраняем изображение в байтовый поток
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    # Возвращаем изображение как ответ
    return Response(img_io.getvalue(), mimetype='image/png')


# API для генерации QR настроек
@app.route('/api/company/<company_uuid>/staff/<staff_uuid>/qr_settings', methods=['GET'])
def generate_settings_qr(company_uuid, staff_uuid):
    # Проверяем, что компания принадлежит пользователю
    company = Company.query.filter_by(uuid=company_uuid).first()
    if not company:
        return jsonify({'message': 'Company not found!'}), 404

    # Проверяем, что сотрудник принадлежит компании
    staff = CompanyStaff.query.filter_by(uuid=staff_uuid, company_id=company.id).first()
    if not staff:
        return jsonify({'message': 'Staff not found!'}), 404

    # Создаем данные для QR настроек
    settings_data = {
        "host": "http://192.168.1.21:5000",
        "salt": company.public_key,
        "passw": staff.staff_token
    }

    # Преобразуем в строку JSON
    settings_json = str(settings_data)

    # Создаем QR-код с настройками
    qr = qrcode.make(
        version=1,
        box_size=10,
        border=4,
        data=settings_json
    )

    # Сохраняем изображение в байтовый поток
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    # Возвращаем изображение как ответ
    return Response(img_io.getvalue(), mimetype='image/png')


# Страница личного кабинета
@app.route('/lk/')
def dashboard():
    return render_template("dashboard.html")


# Существующие маршруты верификации (оставляем как есть)
@app.route('/api/app/verify/create', methods=['POST'])
@company_token_required
def create(company):
    json_data = request.json
    lifetime = json_data.get('lifetime',60)
    mdata = json_data.get('metadata')
    h0 = generate_hash()
    h1 = generate_hash()
    rch = generate_hash()
    uuid_g = uuid.uuid4()
    cr_at = int(time.time())
    expires_at = cr_at + lifetime
    vr = VerificationRequest(
        uuid=str(uuid_g),
        created_at=cr_at,
        expires_at=expires_at,
        mdata=mdata,
        hash_value=h0,
        hash_two=h1,
        rc=rch,
        company_id=company.id  # Связываем запрос с компанией
    )
    db.session.add(vr)
    db.session.commit()
    return jsonify({"uuid": str(uuid_g),"hash": str(h0)})


@app.route('/api/app/verify/1/<h>', methods=['POST'])
def hello_world(h):
    print(request.method)
    print(h)
    print(request.json)
    vr = VerificationRequest.query.filter_by(hash_value=h, status="pending").first()
    if not vr:
        print("NF")
        return jsonify({"status": "error", "message": "verification request not found"})
    company = vr.company_id
    company = Company.query.filter_by(id=company).first()
    if hashlib.md5((company.public_key + h).encode('utf-8')).hexdigest() != request.json['hash']:
        print("IH")
        return jsonify({"status": "error", "message": "invalid hash"})
    return {"success": True, "hash": vr.hash_two, "req_code": vr.rc}, 200


@app.route('/api/app/<uuid>/qr', methods=['GET'])
def qr(uuid):
    # Проверяем, что запрос верификации принадлежит компании
    vr = VerificationRequest.query.filter_by(uuid=uuid, status="pending").first()
    if not vr:
        return jsonify({"status": "error", "message": "verification request not found"}), 404

    qr = qrcode.make(
        version=1,
        box_size=10,
        border=4,
        data=vr.hash_value
    )

    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    return img_io.getvalue(), 200


@app.route('/api/app/<uuid>/status', methods=['GET'])
@company_token_required
def status(company, uuid):
    # Проверяем, что запрос верификации принадлежит компании
    vr = VerificationRequest.query.filter_by(uuid=uuid, company_id=company.id).first()
    if not vr:
        return jsonify({"status": "error", "message": "verification request not found"}), 404
    if vr.expires_at < int(time.time()):
        vr.status = "expired"
        db.session.add(vr)
        db.session.commit()

    return jsonify({"status":vr.status})


@app.route('/api/app/verify/<rc>/', methods=['POST'])
def rcr(rc):
    print(f"Received key: {rc}")
    print(request.json)

    timestamp = request.json.get('timestamp')
    vc = VerificationRequest.query.filter_by(rc=rc).first()
    company = vc.company_id
    company: Company = Company.query.filter_by(id=company).first()
    if not company:
        return jsonify({"status": "error", "message": "verification request not found"}), 404
    usr = User.query.filter_by(id=company.user_id).first()
    if not usr:
        return jsonify({"status": "error", "message": "user not found"}), 404
    if usr.balance < 0.01:
        return jsonify({"status": "error", "message": "balance too low"}), 400
    if not vc:
        return jsonify({"status": "error", "message": "verification request not found"})

    if timestamp:
        if not vc:
            return jsonify({"success": False, "error": "Invalid request"}), 400
        current_time = int(time.time() * 1000)
        if abs(current_time - timestamp) <= 2000:
            if vc.expires_at > current_time / 1000:
                vc.status = 'success'
                db.session.add(vc)
                usr.balance-=0.01
                db.session.add(usr)
                db.session.commit()
                return {"success": True}, 200
            else:
                print("E")
                vc.status = 'expired'
                db.session.add(vc)
                db.session.commit()
                return {"error": "External request failed"}, 400
        else:
            print("Timestamp is too old")
            return {"error": "Timestamp is too old"}, 400
    else:
        print("Timestamp missing")
        return {"error": "Timestamp missing"}, 400


@app.route('/debug')
def debug():
    return render_template("debug.html")


@app.route('/auth')
def auth():
    return render_template("auth.html")


# API для получения информации о текущем пользователе
@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({
        'user': {
            'uuid': current_user.uuid,
            'email': current_user.email,
            'balance': current_user.balance,
            'is_admin': current_user.is_admin
        }
    })

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run("192.168.1.21", 5000, debug=True)