import os
import boto3
import jwt
import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from botocore.config import Config

# Initialize Flask app
app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

# ✅ AWS S3 Configuration (Set in Environment Variables)
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
S3_BUCKET = os.getenv("AWS_S3_BUCKET", "naman-image-app")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")

# ✅ AWS S3 Client Setup
s3_client = boto3.client(
    "s3",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    config=Config(signature_version="s3v4")
)

# ✅ PostgreSQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost:5432/imageDB'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecretkey")

db = SQLAlchemy(app)

# ✅ User Model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def to_dict(self):
        return {"id": self.id, "username": self.username, "name": self.name}

# ✅ Generate JWT Token
def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

@app.route("/")
def home():
    return jsonify({"message": "Welcome to the Flask API"}), 200

# ✅ SIGNUP API
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    name = data.get("name")
    password = data.get("password")

    if not username or not name or not password:
        return jsonify({"error": "Missing fields"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username=username, name=name, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    token = generate_token(new_user.id)

    return jsonify({"message": "User created successfully", "token": token, "user": new_user.to_dict()}), 201

# ✅ LOGIN API
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        token = generate_token(user.id)
        return jsonify({"message": "Login successful", "token": token, "user": user.to_dict()}), 200

    return jsonify({"error": "Invalid credentials"}), 401

# ✅ UPLOAD IMAGE TO S3
@app.route("/upload", methods=["POST"])
def upload_image():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file provided"}), 400

    # Validate File Type
    allowed_types = {'image/jpeg', 'image/png', 'image/gif'}
    if file.content_type not in allowed_types:
        return jsonify({"error": "File type not allowed"}), 400

    file_key = f"images/{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    
    try:
        s3_client.upload_fileobj(file, S3_BUCKET, file_key, ExtraArgs={"ContentType": file.content_type})
        image_url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{file_key}"
        return jsonify({"message": "Upload successful", "image_url": image_url}), 200
    except Exception as e:
        print(f"Error uploading file to S3: {str(e)}")  # Log the error
        return jsonify({"error": str(e)}), 500

# ✅ GET ALL IMAGES FROM S3
@app.route("/images", methods=["GET"])
def get_images():
    try:
        # List objects in the S3 bucket
        objects = s3_client.list_objects_v2(Bucket=S3_BUCKET)
        print("S3 Objects Response:", objects)  # Log the full response from S3

        if "Contents" in objects:
            # Construct image URLs
            image_urls = [
                f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{obj['Key']}"
                for obj in objects["Contents"]
            ]
            return jsonify({"images": image_urls}), 200
        else:
            return jsonify({"images": []}), 200
    except Exception as e:
        print(f"Error listing S3 objects: {str(e)}")  # Log the error
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)