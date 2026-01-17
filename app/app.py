#!/usr/bin/env python3
"""
VulnHub E-commerce Application
Main Flask application file

DISCLAIMER: This application is intentionally vulnerable for educational purposes.
DO NOT deploy this in production or on public-facing servers.
"""

from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import text  # ADDED THIS!
import os
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'vulnerable-secret-key-change-this'  # Intentionally weak
# Get absolute path to the app directory
basedir = os.path.abspath(os.path.dirname(__file__))

# Build full path to database  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data', 'ecommerce.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Check if running in secure mode
SECURE_MODE = os.environ.get('SECURE_MODE', 'false').lower() == 'true'

# Initialize database first
from app.models import db
db.init_app(app)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Import models AFTER db is initialized
from models import User, Product, Order, OrderItem, CartItem, Review

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ============================================================================
# ROUTES - Homepage & Basic Pages
# ============================================================================

@app.route('/')
def index():
    """Homepage with featured products"""
    featured_products = Product.query.limit(8).all()
    return render_template('index.html', products=featured_products)


@app.route('/products')
def products():
    """Product listing page"""
    # Get filter parameters
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    
    categories = ['Electronics', 'Clothing', 'Books', 'Home', 'Sports']
    
    # VULNERABLE: SQL injection in search!
    if search:
        # Raw SQL query - INTENTIONALLY VULNERABLE!
        sql = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
        
        if category:
            sql += f" AND category = '{category}'"
        
        # Execute raw SQL (vulnerable to injection)
        result_rows = db.session.execute(text(sql)).fetchall()
        
        # Convert results to Product objects
        results = []
        for row in result_rows:
            product = Product.query.get(row[0])  # row[0] is the id
            if product:
                results.append(product)
    elif category:
        # Category filter only (still using ORM safely)
        results = Product.query.filter_by(category=category).all()
    else:
        # No filters - show all
        results = Product.query.all()
    
    return render_template('products.html', 
                         products=results, 
                         categories=categories,
                         current_category=category)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Individual product page"""
    product = Product.query.get_or_404(product_id)
    reviews = Review.query.filter_by(product_id=product_id).all()
    
    return render_template('product_detail.html', 
                         product=product, 
                         reviews=reviews)


# ============================================================================
# ROUTES - Authentication
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simple authentication for now
        import hashlib
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        user = User.query.filter_by(username=username, password=password_hash).first()
        
        if user:
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid credentials', 'error')
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('register.html', error='Username already exists')
        
        # Create new user with weak MD5 hash
        import hashlib
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        new_user = User(
            username=username,
            email=email,
            password=password_hash,
            is_admin=False
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


# ============================================================================
# ROUTES - Shopping Cart
# ============================================================================

@app.route('/cart')
@login_required
def view_cart():
    """View shopping cart"""
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    
    total = sum(item.product.price * item.quantity for item in cart_items)
    
    return render_template('cart.html', 
                         cart_items=cart_items, 
                         total=total)


@app.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    """Add item to cart"""
    quantity = int(request.form.get('quantity', 1))
    
    # Check if item already in cart
    cart_item = CartItem.query.filter_by(
        user_id=current_user.id, 
        product_id=product_id
    ).first()
    
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(
            user_id=current_user.id,
            product_id=product_id,
            quantity=quantity
        )
        db.session.add(cart_item)
    
    db.session.commit()
    flash('Item added to cart', 'success')
    return redirect(url_for('view_cart'))


@app.route('/cart/remove/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    """Remove item from cart"""
    cart_item = CartItem.query.get_or_404(item_id)
    
    # VULNERABLE: No authorization check! (IDOR)
    db.session.delete(cart_item)
    db.session.commit()
    
    flash('Item removed from cart', 'success')
    return redirect(url_for('view_cart'))


# ============================================================================
# ROUTES - Orders (Vulnerable to IDOR)
# ============================================================================

@app.route('/orders')
@login_required
def my_orders():
    """View user's order history"""
    # VULNERABLE: Shows all orders in vulnerable mode
    if SECURE_MODE:
        orders = Order.query.filter_by(user_id=current_user.id).all()
    else:
        # Intentionally vulnerable - shows all orders
        orders = Order.query.all()
    
    return render_template('orders.html', orders=orders)


@app.route('/order/<int:order_id>')
@login_required
def view_order(order_id):
    """View specific order (IDOR vulnerability)"""
    order = Order.query.get_or_404(order_id)
    
    # VULNERABLE: No authorization check in vulnerable mode!
    if SECURE_MODE:
        if order.user_id != current_user.id and not current_user.is_admin:
            flash('Access denied', 'error')
            return redirect(url_for('my_orders'))
    
    return render_template('order_detail.html', order=order)


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    """Checkout and create order"""
    if request.method == 'POST':
        cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
        
        if not cart_items:
            flash('Cart is empty', 'error')
            return redirect(url_for('view_cart'))
        
        # Calculate total
        total = sum(item.product.price * item.quantity for item in cart_items)
        
        # Create order
        order = Order(
            user_id=current_user.id,
            total_price=total,
            status='pending',
            shipping_address=request.form.get('address', '')
        )
        db.session.add(order)
        db.session.flush()
        
        # Create order items
        for cart_item in cart_items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=cart_item.product_id,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )
            db.session.add(order_item)
            
            # Remove from cart
            db.session.delete(cart_item)
        
        db.session.commit()
        
        flash(f'Order #{order.id} placed successfully!', 'success')
        return redirect(url_for('view_order', order_id=order.id))
    
    # GET request - show checkout form
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    
    return render_template('checkout.html', cart_items=cart_items, total=total)


# ============================================================================
# ROUTES - Reviews (XSS vulnerability)
# ============================================================================

@app.route('/product/<int:product_id>/review', methods=['POST'])
@login_required
def add_review(product_id):
    """Add product review (XSS vulnerability)"""
    rating = int(request.form.get('rating', 3))
    comment = request.form.get('comment', '')
    
    # VULNERABLE: No input sanitization!
    review = Review(
        product_id=product_id,
        user_id=current_user.id,
        rating=rating,
        comment=comment  # XSS payload stored here!
    )
    
    db.session.add(review)
    db.session.commit()
    
    flash('Review added successfully', 'success')
    return redirect(url_for('product_detail', product_id=product_id))


# ============================================================================
# ROUTES - Admin Panel
# ============================================================================

@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard"""
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    stats = {
        'total_users': User.query.count(),
        'total_products': Product.query.count(),
        'total_orders': Order.query.count(),
        'pending_orders': Order.query.filter_by(status='pending').count()
    }
    
    return render_template('admin/dashboard.html', stats=stats)


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', 
                         error='Page not found'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', 
                         error='Internal server error'), 500


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Initialize database with tables"""
    with app.app_context():
        db.create_all()
        print("[+] Database initialized!")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    # Create database directory if it doesn't exist
    db_dir = os.path.join(basedir, 'data')
    os.makedirs(db_dir, exist_ok=True)
    
    # Create database if it doesn't exist
    db_path = os.path.join(db_dir, 'ecommerce.db')
    if not os.path.exists(db_path):
        print("[*] Database not found, creating...")
        init_db()
        print(f"[!] Database created at: {db_path}")
        print("[!] Run 'python app/data/seed_data.py' to populate with sample data")
    
    # Display startup message
    mode = "SECURE" if SECURE_MODE else "VULNERABLE"
    print(f"\n{'='*60}")
    print(f"VulnHub E-commerce - Running in {mode} mode")
    print(f"{'='*60}\n")
    
    if not SECURE_MODE:
        print("⚠️  WARNING: This application is intentionally vulnerable!")
        print("⚠️  Do NOT deploy this in production!\n")
    
    print("Default credentials:")
    print("  Admin: admin / admin123")
    print("  User:  user / password\n")
    print(f"Database location: {db_path}")
    print(f"Access at: http://localhost:5001\n")
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=True  # Intentionally enabled for demonstration
    )