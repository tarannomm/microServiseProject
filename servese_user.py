from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_swagger import swagger

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/user_db'# replace it for postgres
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)

# PostgreSQL User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), nullable=False)

# Cart Model
class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.String(24), nullable=False)  # MongoDB ObjectId as string
    quantity = db.Column(db.Integer, nullable=False, default=1)
# MongoDB connection for products
client = MongoClient('mongodb://localhost:27017/') # replace it for mongodb
product_db = client['product_db']
products_collection = product_db['products']

@app.route('/swagger.json')
def spec():
    return jsonify(swagger(app))
# User Registration
@app.route('/register', methods=['POST'])
def register():
    """
    User Registration
    ---
    parameters:
      - name: username
        description: Username of the user
        required: true
        type: string
      - name: password
        description: Password for the user
        required: true
        type: string
      - name: email
        description: Email address of the user
        required: true
        type: string
    responses:
      201:
        description: User created
      400:
        description: User already exists
    """
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'User already exists'}), 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], password=hashed_password, email=data['email'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created'}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    """
    User Login
    ---
    parameters:
      - name: username
        description: Username of the user
        required: true
        type: string
      - name: password
        description: Password of the user
        required: true
        type: string
    responses:
      200:
        description: Access token generated
      401:
        description: Invalid credentials
    """
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username})
        return jsonify(access_token=access_token), 200
    return jsonify({'error': 'Invalid credentials'}), 401

# Get User Profile
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    """
    Get User Profile
    ---
    responses:
      200:
        description: User profile data
      404:
        description: User not found
    """
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()
    if user:
        return jsonify({
            'username': user.username,
            'email': user.email
        }), 200
    return jsonify({'error': 'User not found'}), 404

# Update User Profile
@app.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """
    Update User Profile
    ---
    parameters:
      - name: email
        description: New email address of the user
        required: false
        type: string
      - name: password
        description: New password for the user
        required: false
        type: string
    responses:
      200:
        description: Profile updated
      404:
        description: User not found
    """
    current_user = get_jwt_identity()
    data = request.json
    user = User.query.filter_by(username=current_user['username']).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if 'email' in data:
        user.email = data['email']

    if 'password' in data:
        user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    db.session.commit()
    return jsonify({'message': 'Profile updated'}), 200

# Get all products (for all users)
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    """
    Get All Products
    ---
    responses:
      200:
        description: A list of products
    """
    products = list(products_collection.find())
    for product in products:
        product['_id'] = str(product['_id'])
    return jsonify(products)


# Add a product to the cart
@app.route('/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.json
    product_id = data['product_id']
    quantity = data.get('quantity', 1)

    existing_item = CartItem.query.filter_by(user_id=user.id, product_id=product_id).first()
    if existing_item:
        existing_item.quantity += quantity
    else:
        new_item = CartItem(user_id=user.id, product_id=product_id, quantity=quantity)
        db.session.add(new_item)
    
    db.session.commit()
    return jsonify({'message': 'Product added to cart'}), 201
  
# View the cart
@app.route('/cart', methods=['GET'])
@jwt_required()
def view_cart():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    cart_items = CartItem.query.filter_by(user_id=user.id).all()
    items = []
    for item in cart_items:
        product = products_collection.find_one({'_id': ObjectId(item.product_id)})
        if product:
            item_info = {
                'product_id': item.product_id,
                'quantity': item.quantity,
                'product_details': {
                    'name': product['name'],
                    'price': product['price'],
                    'description': product.get('description', '')
                }
            }
            items.append(item_info)
    
    return jsonify(items)
# Purchase products
@app.route('/purchase', methods=['POST'])
@jwt_required()
def purchase():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    cart_items = CartItem.query.filter_by(user_id=user.id).all()
    
    if not cart_items:
        return jsonify({'error': 'Cart is empty'}), 400
    
    # Simulate purchase processing (e.g., payment processing can go here)

    # Clear the cart after purchase
    for item in cart_items:
        db.session.delete(item)
    
    db.session.commit()
    return jsonify({'message': 'Purchase successful'}), 200

if __name__ == '__main__':
    db.create_all()  # Create database tables for users
    app.run(debug=True)