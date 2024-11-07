from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy  # Correct import for SQLAlchemy
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_swagger import swagger
client = MongoClient('mongodb+srv://tazimi296:<db_password>@blogs.qka4q.mongodb.net/?retryWrites=true&w=majority&appName=blogs') # replace it for mongodb
product_db = client['products']
products_collection = product_db['products']
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'k18a41t15' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:TeNckomGwk6WDdEOefr7deXk@products:5432/postgres' 
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


@app.route('/swagger.json')
def spec():
    return jsonify(swagger(app))
    
# User Registration
@app.route('/register', methods=['POST'])
def register():
 
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
    for item in cart_items:
        db.session.delete(item)
    
    db.session.commit()
    return jsonify({'message': 'Purchase successful'}), 200


# Create a product (admin only)
@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    current_user = get_jwt_identity()
    if current_user.get('role') != 'admin':
        return jsonify({'error': 'Access forbidden Admins only'}), 403
    
    product_data = request.json
    products_collection.insert_one(product_data)
    return jsonify(product_data), 201

# Update a product (admin only)
@app.route('/products/<id>', methods=['PUT'])
@jwt_required()
def update_product(id);
    current_user = get_jwt_identity()
    if current_user.get('role') != 'admin':
        return jsonify({'error': 'Access forbidden Admins only'}), 403
    
    product_data = request.json
    result = products_collection.update_one({'_id': ObjectId(id)}, {'$set': product_data})
    if result.matched_count > 0:
        updated_product = products_collection.find_one({'_id': ObjectId(id)})
        updated_product['_id'] = str(updated_product['_id'])
        return jsonify(updated_product)
    return jsonify({'error': 'Product not found'}), 404

# Delete a product (admin only)
@app.route('/products/<id>', methods=['DELETE'])
@jwt_required()
def delete_product(id);
    current_user = get_jwt_identity()
    if current_user.get('role') != 'admin':
        return jsonify({'error': 'Access forbidden Admins only'}), 403
    
    result = products_collection.delete_one({'_id': ObjectId(id)})
    if result.deleted_count > 0:
        return jsonify({'message': 'Product deleted'})
    return jsonify({'error': 'Product not found'}), 404

if __name__ == '__main__':
    #db.create_all() 
    app.run(debug=True)