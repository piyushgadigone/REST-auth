#!/usr/bin/env python
import os
from flask import Flask, render_template, abort, request, jsonify, g, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from login import LoginForm
from register import RegisterForm
import requests
import json
import uuid
import time

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['GCM_API_KEY'] = 'AIzaSyDx4_u1re-Gcn5Vfyv33Bm5cfZ31EipVws';
app.config['GCM_URL'] = 'https://android.googleapis.com/gcm/send';

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

# Database models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user

class Registration(db.Model):
    __tablename__ = 'registrations'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    registration_id = db.Column(db.String(128))

class IP(db.Model):
    __tablename__ = 'ip'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    token = db.Column(db.String(64))
    browser_ip = db.Column(db.String(64))
    device_ip = db.Column(db.String(64))


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
            registration = Registration.query.filter_by(username=form.username.data).first()
            if not registration:
                return 'Device is not registered'
            else:
                headers = {'Content-Type': 'application/json', 'Authorization':'key=%s' % app.config['GCM_API_KEY']}
                token = uuid.uuid4().hex
                data = {'registration_ids':['%s' % registration.registration_id], 'data': {'token':'%s' % token, 'username': '%s' % form.username.data}}
                r = requests.post(app.config['GCM_URL'], data=json.dumps(data), headers=headers)

		# Add the browser IP address to the database
		ip = IP(browser_ip=request.remote_addr)
		ip.username = form.username.data
		ip.token = token
		db.session.add(ip)
		db.session.commit()
                return render_template('login_progress.html', username=form.username.data, token=token)
        
	else:
            return render_template('login.html', form=form, success=False)

    elif request.method == 'GET':  
        return render_template('login.html', form=form, success=True)

@app.route('/checkDeviceIP', methods=['GET'])
def checkDeviceIP():
    username = request.args.get('username')
    token = request.args.get('token')
    ip_updated = IP.query.filter_by(username=username).first()
    if not ip_updated:
        return jsonify({'result':'No login attempted by this user. Possible attack to the system!'})
    db.session.delete(ip_updated)
    db.session.commit()
    if token != ip_updated.token:
        return jsonify({'result':'Token values dont match. Possible attack to the system!'})
    elif ip_updated.device_ip and len(ip_updated.device_ip) > 0:
        if (ip_updated.browser_ip == ip_updated.device_ip):
            return jsonify({'result':'Login successful'})
        else:
            return jsonify({'result':'Device and browser ip doesnt match'})

    return jsonify({'result':'Didnt hear back from the device. Login using 2-step auth.'})

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('register.html', form=form, success=False, message="User already exists")
        elif password != form.confirm_password.data:
            return render_template('register.html', form=form, success=False, message="Two passwords dont match")
        elif (len(username) < 1 or len(password) < 1):
            return render_template('register.html', form=form, success=False, message="Enter valid username and password")
        else:
            user = User(username=username)
            user.hash_password(password)
            db.session.add(user)
            db.session.commit()
            return "User '" +  username + "'' registered. Register with '" + username + "'' on your device."

    elif request.method == 'GET':
        return render_template('register.html', form=form, success=True, message='')

@app.route('/registrationId', methods=['POST'])
def registrationId():
    username = request.json.get('username')
    registrationId = request.json.get('registrationId')
    user = User.query.filter_by(username=username).first()
    reg = Registration.query.filter_by(username=username).first()
    if not user:
        return jsonify({'result': 'User does not exist'})
    elif (not registrationId or len(registrationId) < 1):
        return jsonify({'result': 'Invalid registration id'})
    elif reg:
        return jsonify({'result': 'User is already registered'})
    else:
        registration = Registration(registration_id=registrationId)
        registration.username = username
        db.session.add(registration)
        db.session.commit()
        return jsonify({'result': 'Registration id successfully added'})

@app.route('/ip', methods=['POST'])
def ip():
    username = request.json.get('username')
    token = request.json.get('token')
    ip = IP.query.filter_by(username=username).first()
    if not ip:
        return jsonify({'result':'User has not attempted to login. Possible attack to the system!'})
    elif ip.token != token:
        return jsonify({'result':'Incorrect token. Possible attack to the system!'})
    else:
        ip.device_ip = request.remote_addr
        db.session.add(ip)
        db.session.commit()
	return jsonify({'result':'Device IP successfully reported'})

if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(host='0.0.0.0')
