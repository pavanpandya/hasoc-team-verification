from flask import Flask, current_app, request, jsonify, Response, json, make_response
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
from functools import wraps
import pymongo
import jwt
import datetime
import os

app = Flask(__name__)

# Instantiate the object of bcrypt
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
app.config['CORS_HEADERS'] = 'application/json'

# Cross-Origin Resource Sharing
CORS(app)

# AUTH TOKEN
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'Token is invalid !!'}), 401
        return  f(*args, **kwargs)
    return decorated

def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            if(data['isadmin']):
                pass
            else:
                return jsonify({'message' : 'Token is invalid !!'}), 401    
        except:
            return jsonify({'message' : 'Token is invalid !!'}), 401
        return  f(*args, **kwargs)
    return decorated


# DATABASE CONFIGURATION
try:
    mongo = pymongo.MongoClient()
    db = mongo.hasoc
    print('\n\n*********************************\n\n')
    print("SUCCESS")
    print('\n\n*********************************\n\n')
    mongo.server_info()
except Exception as ex: 
    print('\n\n*********************************\n\n')
    print(ex)
    print('\n\n*********************************\n\n')


@app.route('/login', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
def login():
    try:
        if request.method=='POST':
            form_data = request.get_json()
            name = form_data['name']
            password = form_data['password']
            if(name!='' and password!=''):
                data = list(db.users.find({'name':name}))
                if(len(data)==0):
                    return Response(status=404, response=json.dumps({'message':'user does not exist'}), mimetype='application/json')
                else:
                    data = data[0]
                    db_password_hash = data['password_hash']
                    if(bcrypt.check_password_hash(db_password_hash, password)):
                        token = jwt.encode({'name' : name, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
                        print(token)
                        print(type(token))
                        # return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
                        return make_response(jsonify({'token' : token}), 201)
                    else:
                        return Response(status=402, response=json.dumps({'message':'Invalid password'}), mimetype='application/json')
            else:
                return Response(status=400, response=json.dumps({'message':'Bad request'}), mimetype='application/json')
    except Exception as Ex:
        print('\n\n*********************************')
        print(Ex)
        print('*********************************\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")


@app.route('/admin/user', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@admin_token_required
def create_or_display_user():
    try:
        if request.method == 'POST':
            data = request.get_json()
            name = data['name']
            email = data['email']
            password = data['password']
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            isadmin = data['isadmin']
            d = db.users.insert_one({'name':name,'email':email,'password_hash':password_hash,"adminAccess":isadmin})
            return Response(response=json.dumps({'message': 'User created successfully'}), status=200, mimetype="application/json")
        else:
            user = {}
            u = list(db.users.find({'adminAccess':1}, {'_id': 0}))
            for usr in u:
                name = usr['name']
                verify_count = db.teams.count_documents({'verified_by':name})
                if name in user:
                    user[name].append(verify_count)
                else:
                    user[name] = verify_count
                # print(usr)
                # db.users.update({ "name": name }, {'$set': {"no_of_files_verified" : verify_count}})
            return make_response(jsonify({'Count per User' : user}), 200)
    except pymongo.errors.DuplicateKeyError:
        return Response(
            response=json.dumps({'message':'duplicate username'}),status=403,mimetype='application/json')
    except Exception as Ex:
        print('\n\n*********************************')
        print(Ex)
        print('*********************************\n\n')
        return Response(response=json.dumps({'message': Ex}), status=500, mimetype="application/json")

@app.route('/test', methods=['GET','POST'])
@token_required
def test():
    try:
        if request.method == 'POST':
            return Response(response=json.dumps({'message': 'Successfully'}), status=200, mimetype="application/json")
        else:
            return Response(response=json.dumps({'message': 'Unsuccessfully'}), status=200, mimetype="application/json")
    except Exception as Ex:
        print('\n\n*********************************')
        print(Ex)
        print('*********************************\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")


"""
Approved by Whom
"""
pass


"""
Count the total vertification of files
"""
@app.route('/verified_count', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
def count_total_verified_files():
    """
    Display the total count of vertification done.
    """
    try:
        if request.method == 'GET':
            total_count = len(list(db.teams.find({'status': 'verified'})))
            return make_response(jsonify({'Total Count' : total_count}), 200)
    except Exception as Ex:
        print('\n\n*********************************')
        print(Ex)
        print('*********************************\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")


"""
Count the total files yet to be approved
"""
@app.route('/pending_count', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
def count_total_pending_files():
    """
    Display the total count of file yet to be approved.
    """
    try:
        if request.method == 'GET':
            total_count = len(list(db.teams.find({'status': 'pending'})))
            return make_response(jsonify({'Total Count' : total_count}), 200)
    except Exception as Ex:
        print('\n\n*********************************')
        print(Ex)
        print('*********************************\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")


"""
Count the total files that are rejected
"""
@app.route('/rejected_count', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
def count_total_pending_files():
    """
    Display the total count of files that are rejected.
    """
    try:
        if request.method == 'GET':
            total_count = len(list(db.teams.find({'status': 'reject'})))
            return make_response(jsonify({'Total Count' : total_count}), 200)
    except Exception as Ex:
        print('\n\n*********************************')
        print(Ex)
        print('*********************************\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")


"""
Delete a User
"""
@app.route('/delete', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
def delete_user():
    """
    Deletes a particular user.
    """
    try:
        if request.method == 'POST':
            data = request.get_json()
            email = data['email']
            if(email!=''):
                current_user = len(list(db.users.find({'email': email})))
                if current_user:
                    d = db.users.remove({'email':email})
                    return Response(response=json.dumps({'message': 'User Deleted successfully'}), status=200, mimetype="application/json")
                else:
                    return Response(response=json.dumps({'message': 'User Does not exist'}), status=200, mimetype="application/json")
            else:
                return Response(response=json.dumps({'message': 'Please enter the email address'}), status=200, mimetype="application/json")
    except Exception as Ex:
        print('\n\n*********************************')
        print(Ex)
        print('*********************************\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


if __name__=="__main__":
    app.run(debug=True)