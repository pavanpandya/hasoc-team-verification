from flask import Flask, request, Response, json, jsonify, make_response
from datetime import datetime, timedelta
from functools import wraps
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
import jwt
import pymongo
import os

app = Flask(__name__)

# Instantiate the object of bcrypt
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
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


"""
Login
"""
@app.route('/login', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
def login():
    try:
        if request.method=='POST':
            form_data = request.get_json()
            name = form_data['name']
            password = form_data['password']
            isAdmin = "1"
            if(name!='' and password!=''):
                data = list(db.users.find({'_id':name}))
                if(len(data)==0):
                    return Response(status=404, response=json.dumps({'message':'user does not exist'}), mimetype='application/json')
                else:
                    data = data[0]
                    db_password_hash = data['password_hash']
                    if(bcrypt.check_password_hash(db_password_hash, password)):
                        if(data['adminAccess']):
                            token = jwt.encode({
                                'uname': name,
                                # 'isadmin':data['adminAccess'],
                                'exp' : datetime.utcnow() + timedelta(hours = 4)}, app.config['SECRET_KEY']) 
                            return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
                        else:
                            if(isAdmin):
                                return Response(status=401, response=json.dumps({'message':'invalid user request'}), mimetype='application/json')
                            else:
                                token = jwt.encode({
                                    'uname': name,
                                    # 'isadmin':data['adminAccess'],
                                    'exp' : datetime.utcnow() + timedelta(hours = 4)}, app.config['SECRET_KEY']) 
                                return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
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


"""
Change Password
"""
def change_password():
    pass

@app.route('/admin/user', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
# @admin_token_required
def user():
    """
    creates a new user or display the count of vertification done by a particular user
    """
    try:
        if request.method == 'POST':
            data = request.get_json()
            name = data['name']
            email = data['email']
            password = data['password']
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            isadmin = data['isadmin']
            d = db.users.insert_one({'_id':name,'email':email,'password_hash':password_hash,"adminAccess":isadmin})
            return Response(response=json.dumps({'message': 'User created successfully'}), status=200, mimetype="application/json")
        else:
            user = dict()
            u = list(db.users.find({},{'email':1,'adminAccess':1}))
            for user in u:
                name = user['_id']
                verify_count = db.verified_teams.count_documents({'verified_by':name})
                user['verified'] = verify_count
            user['users'] = u #doubt
            return user
    except pymongo.errors.DuplicateKeyError:
        return Response(
            response=json.dumps({'message':'duplicate username'}),status=403,mimetype='application/json')
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
Add approved file to database
"""
pass


"""
Count the total vertification of files
"""
pass


"""
Count the total vertification of files by an Individual
"""
# def get_dashboard_statatics():
#     try:
#         data = list(db.teams.find())
#         userwise_count = dict()
#         total_team_verified = 0
#         storywise_tweets_count = list(db.teams.aggregate([{'$group':{'_id':'$story','tweets_count':{'$sum':'$tweets_count'}}}])) #-----------
#         total = 0
#         storywise_count = dict()
#         for story in storywise_tweets_count:
#             story_name = story['_id']
#             if(story_name not in storywise_count):
#                 storywise_count[story_name] = {}
#             storywise_count[story_name]['no_of_status'] = db.teams.count_documents({'story':story_name})
#             storywise_count[story_name]['tweets_count'] = story['tweets_count']
#             total_tweets_story += story['tweets_count']
#             storywise_count[story_name]['annotated_by_one'] = db.teams.count_documents({'story':story_name,'annotated_by.0':{'$exists':True}})
#             total_annotated_count['by_one'] += storywise_count[story_name]['annotated_by_one']
#             total += storywise_count[story_name]['no_of_status'] 
#         users = list(db.users.find({},{'_id':1}))
#         userwise_count['assigned_total'] = 0
#         userwise_count['annotated_total'] = 0
#         for user in users:
#             user = user['_id']
#             if(user not in userwise_count):
#                 userwise_count[user] = {}
#             userwise_count[user]['assigned'] = db.teams.count_documents({'assigned_to':user})
#             userwise_count[user]['annotated'] = db.teams.count_documents({'annotated_by':user})
#             userwise_count['assigned_total'] += userwise_count[user]['assigned']
#             userwise_count['annotated_total'] += userwise_count[user]['annotated']
#             if('tweets_annotated_count' not in userwise_count[user]):
#                 userwise_count[user]['tweets_annotated_count'] = 0
#             #storywise_annotated_tweets_count = {}   
#             for tweet_data in data:
#                 if(user in tweet_data['annotated_by']):
#                     userwise_count[user]['tweets_annotated_count'] += len(tweet_data[user].keys())
#                     total_tweets_annotated += len(tweet_data[user].keys())
#         return {'storywise_count':storywise_count,'userwise_count':userwise_count,'total_annotated_count':total_annotated_count,'total_status':total, 'total_tweets_story':total_tweets_story,'total_tweets_annotated':total_tweets_annotated}
#     except Exception as Ex:
#         print('#'*10)
#         print(Ex)
#         print('#'*10)
#         return Ex


"""
Count the total files yet to be approved
"""
pass


"""
Delete a User
"""
pass


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


if __name__=="__main__":
    app.run(debug=True)