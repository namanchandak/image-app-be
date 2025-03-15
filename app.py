from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend interaction

# PostgreSQL Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost:5432/imageDB'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define a User Model
class User(db.Model):
    __tablename__ = "users"  # ✅ Fix the reserved keyword issue

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hash passwords in production

    def to_dict(self):
        return {"id": self.id, "username": self.username, "name": self.name}

# API Endpoints

@app.route("/")
def home():
    return jsonify({"message": "Welcome to the Flask API"}), 200

# Signup Endpoint
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    name = data.get("name")
    password = data.get("password")  # Hash this in production

    if not username or not name or not password:
        return jsonify({"error": "Missing fields"}), 400

    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    # Create new user
    new_user = User(username=username, name=name, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully", "user": new_user.to_dict()}), 201

# Login Endpoint
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username, password=password).first()
    
    if user:
        return jsonify({"message": "Login successful", "user": user.to_dict()}), 200
    return jsonify({"error": "Invalid credentials"}), 401

# Run the Flask app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)