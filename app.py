from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

@app.route("/user", methods = ["GET"])
def get_all_users():
    return""

app.route("/user/<user_id>", methods = ["GET"])
def get_one_user():
    return ""


@app.route("/user", methods = ["POST"])
def create_user():
    return ""

@app.route("/user/<user_id>", methods = ["PUT"])
def promote_user():
    return ""

@app.route("/user/<user_id>", methods = ["DELETE"])
def delete_user():
    return ""


if __name__ == "__main__":
    app.run(debug = True, port = 2020)