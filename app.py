from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

from models import db, User, Task
from extensions import db as ext_db

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///taskmanager.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key-change-this')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

db.init_app(app)
jwt = JWTManager(app)

# Create tables
with app.app_context():
    db.create_all()

# -------- AUTH ROUTES --------
@app.route('/api/v1/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # default 'user'
    
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists"}), 400
    
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/api/v1/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token, role=user.role), 200
    
    return jsonify({"msg": "Bad username or password"}), 401

# -------- TASK ROUTES --------
@app.route('/api/v1/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    # Admin chuste anni tasks, User chuste thana tasks matrame
    if user.role == 'admin':
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(user_id=current_user_id).all()
    
    return jsonify([task.to_dict() for task in tasks]), 200

@app.route('/api/v1/tasks', methods=['POST'])
@jwt_required()
def create_task():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    task = Task(
        title=data.get('title'),
        description=data.get('description'),
        priority=data.get('priority', 'Medium'),
        status=data.get('status', 'Pending'),
        user_id=current_user_id
    )
    db.session.add(task)
    db.session.commit()
    
    return jsonify(task.to_dict()), 201

@app.route('/api/v1/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    task = Task.query.get_or_404(task_id)
    
    # Admin or owner matrame update cheyali
    if user.role != 'admin' and task.user_id != current_user_id:
        return jsonify({"msg": "Not authorized"}), 403
    
    data = request.get_json()
    task.title = data.get('title', task.title)
    task.description = data.get('description', task.description)
    task.priority = data.get('priority', task.priority)
    task.status = data.get('status', task.status)
    db.session.commit()
    
    return jsonify(task.to_dict()), 200

@app.route('/api/v1/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    task = Task.query.get_or_404(task_id)
    
    if user.role != 'admin' and task.user_id != current_user_id:
        return jsonify({"msg": "Not authorized"}), 403
    
    db.session.delete(task)
    db.session.commit()
    
    return jsonify({"msg": "Task deleted"}), 200

if __name__ == '__main__':
    app.run(debug=True)
