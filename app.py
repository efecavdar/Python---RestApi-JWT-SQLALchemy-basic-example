# importing libraries
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

# Configuration for flask and sqlalchemy
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Define the database
db = SQLAlchemy(app)

# For User table in database
class User(db.Model):   #type:ignore
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

# For todo table in database
class Todo(db.Model):  #type:ignore
    id = db.Column(db.Integer, primary_key = True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

    
# error handling for Bad Request (400)
@app.errorhandler(400)
def handle_400_error(_error):
    return make_response(jsonify({"error" : "VERY VERY BAD REQUEST"}), 400)

# error handling for Not Found (404)
@app.errorhandler(404)
def handle_404_error(_error):
    return make_response(jsonify({"error" : "THERE IS NOTHING TO SEE!!"}), 404)
    
# error handling for Method Not Allowed (405)
@app.errorhandler(405)
def handle_405_error(_error):
    return make_response(jsonify({"error" : "THIS METHOD IS NOT ALLOWED"}), 405)

@app.errorhandler(500)
def handle_500_error(_error):
    return make_response(jsonify({"error" : "INTERNAL SERVER ERROR"}), 500)    

# For Json Web Token Authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'token is missing'}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message' : 'token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Getting all user list from database (only admin can do this)
@app.route("/user", methods = ["GET"])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'you are not allowed to do this'}), 401

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data["public_id"] = user.public_id
        user_data["name"] = user.name
        user_data["password"] = user.password
        user_data["admin"] = user.admin
        output.append(user_data)

    return jsonify({"users" : output })

# Getting one user from database with public_id (only admin can do this)
@app.route("/user/<public_id>", methods = ["GET"])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'you are not allowed to do this'}), 401

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({"error": "No user found"}), 404

    user_data = {}
    user_data["public_id"] = user.public_id
    user_data["name"] = user.name
    user_data["password"] = user.password
    user_data["admin"] = user.admin
    
    return jsonify({"user" : user_data})

# Creating a new user (only admin can do this)
@app.route("/user", methods = ["POST"])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'you are not allowed to do this'}), 401

    if request is None:
        data = request.get_json()
    else:
        return(make_response(jsonify({"error" : "NO DATA FOUND"}), 400))

    hashed_password = generate_password_hash(data["password"], method = "sha256")

    new_user = User(public_id = str(uuid.uuid4()), name = data["name"], password = hashed_password, admin = False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message" : "New user created"})

# Updating/promoting users (only admin can do this)
@app.route("/user/<public_id>", methods = ["PUT"])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'you are not allowed to do this'}), 401

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({"error": "No user found"}), 404

    # Promoted
    user.admin = True
    db.session.commit()

    return jsonify({"message" : "User has been promoted"})

# Delete a user from the database
@app.route("/user/<public_id>", methods = ["DELETE"])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'you are not allowed to do this'}), 401

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({"error": "No user found"}), 404

    db.session.delete(user)
    db.session.commit()
    
    return jsonify({"message" : "User has been deleted"})

# Login route for api (Basic Authentication)
@app.route("/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    user = User.query.filter_by(name = auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, "exp" : datetime.datetime.now() + datetime.timedelta(minutes = 30)}, app.config["SECRET_KEY"])

        return jsonify({'token': token.decode("UTF-8")})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

# Get all todos from the database
@app.route('/todo', methods = ['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id = current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data["id"] = todo.id
        todo_data["text"] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify({"todos" : output})

# Get one todo from database
@app.route('/todo/<todo_id>', methods = ['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id = todo_id, user_id = current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!!'})
    
    todo_data = {}
    todo_data["id"] = todo.id
    todo_data["text"] = todo.text
    todo_data['complete'] = todo.complete

    return jsonify(todo_data)
    
# Creating a new todo 
@app.route('/todo', methods = ['POST'])
@token_required
def create_todo(current_user):
    if request is None:
        data = request.get_json()
    else:
        return make_response(jsonify({'error' : 'NO DATA FOUND'}), 400)

    new_todo = Todo(text = data['text'], complete = False, user_id = current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message' : 'todo created!!'})

# Updating the todo for completed tasks
@app.route('/todo/<todo_id>', methods = ['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id = todo_id, user_id = current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!!'})

    todo.complete = True
    db.session.commit()

    return jsonify({'message' : 'todo has been completed!!'})

# Delete a specific todo from the database
@app.route('/todo/<todo_id>', methods = ['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id = todo_id, user_id = current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!!'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message' : 'todo has been deleted!!'})

# Run the app
if __name__ == "__main__":
    app.run(debug = True, port = 2020)