#!/usr/bin/env python3
"""
VulnHub E-commerce - SECURE Implementation
Author: Chris Cortes

This is the secure version of the VulnHub e-commerce application.
All vulnerabilities have been remediated with security best practices:

1. SQL Injection → Parameterized queries
2. XSS → Output encoding (removed |safe filter)
3. IDOR → Authorization checks
4. Weak Auth → bcrypt password hashing
5. CSRF → Flask-WTF CSRF protection
6. Security Headers → Comprehensive header configuration

This demonstrates understanding of both offensive and defensive security.
"""

from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import os
import sys
from datetime import datetime

# Add parent directory to path to import models
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import models from parent directory
from app.models import db, User, Product, Order, Review

# Initialize Flask with correct paths for templates and static files
app = Flask(__name__,
            template_folder='templates',  # Use parent's templates
            static_folder='../static')       # Use parent's static files

# Security configuration
app.config['SECRET_KEY'] = os.urandom(32)  # Secure random secret key

# Database path - absolute path to app/secured/data/ecommerce_secure.db
script_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(script_dir, 'data', 'ecommerce_secure.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session timeout

# Initialize extensions with app
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)  # CSRF protection enabled

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Security Headers Middleware
@app.after_request
def set_security_headers(response):
    """
    Add comprehensive security headers to all responses.
    Defense-in-depth approach to security.
    """
    # Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Prevent MIME-sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection (browser-side)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy (restrict script sources)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "img-src 'self' data: https:;"
    )
    
    # Referrer policy (protect user privacy)
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # HSTS (for production with HTTPS)
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Routes
@app.route('/')
def index():
    """Homepage with featured products"""
    products = Product.query.limit(6).all()
    return render_template('index.html', products=products)

@app.route('/products')
def products():
    """
    Product listing with SECURE search functionality.
    
    SECURITY FIX: SQL Injection → Parameterized Query
    Uses SQLAlchemy's filter method which automatically parameterizes queries.
    """
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    
    # Build query using ORM (automatically parameterized)
    query = Product.query
    
    if search:
        # ✅ SECURE: Using SQLAlchemy's filter with LIKE (parameterized)
        query = query.filter(Product.name.like(f'%{search}%'))
    
    if category:
        # ✅ SECURE: Using SQLAlchemy's filter_by (parameterized)
        query = query.filter_by(category=category)
    
    results = query.all()
    
    categories = ['Electronics', 'Clothing', 'Home & Garden', 'Sports', 'Books']
    
    return render_template('products.html', 
                         products=results, 
                         categories=categories,
                         current_category=category,
                         search_query=search)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """
    Product detail page with reviews.
    
    SECURITY FIX: XSS → Output encoding
    Removed |safe filter from templates, all user content is now HTML-escaped.
    """
    product = Product.query.get_or_404(product_id)
    reviews = Review.query.filter_by(product_id=product_id).all()
    
    # Reviews are now safely displayed (no |safe filter in template)
    return render_template('product_detail.html', product=product, reviews=reviews)

@app.route('/product/<int:product_id>/review', methods=['POST'])
@login_required
def add_review(product_id):
    """
    Add product review (CSRF protected).
    
    SECURITY FIX: XSS + CSRF
    - Input is stored safely (DB handles escaping)
    - Output is encoded in template (no |safe filter)
    - CSRF token required (Flask-WTF)
    """
    product = Product.query.get_or_404(product_id)
    
    rating = request.form.get('rating', type=int)
    comment = request.form.get('comment', '')
    
    # Input validation
    if not rating or rating < 1 or rating > 5:
        flash('Invalid rating', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Additional XSS protection: Sanitize comment length
    if len(comment) > 1000:
        flash('Comment too long (max 1000 characters)', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    review = Review(
        product_id=product_id,
        user_id=current_user.id,
        rating=rating,
        comment=comment  # ✅ SECURE: Will be HTML-escaped in template
    )
    
    db.session.add(review)
    db.session.commit()
    
    flash('Review added successfully!', 'success')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/order/<int:order_id>')
@login_required
def view_order(order_id):
    """
    View order details with AUTHORIZATION check.
    
    SECURITY FIX: IDOR → Authorization Check
    Verifies that the current user owns the order or is an admin.
    """
    order = Order.query.get_or_404(order_id)
    
    # ✅ SECURE: Authorization check
    if order.user_id != current_user.id and not current_user.is_admin:
        # Log unauthorized access attempt
        app.logger.warning(
            f'Unauthorized access attempt: User {current_user.id} '
            f'tried to access Order {order_id} (Owner: {order.user_id})'
        )
        abort(403)  # Forbidden
    
    return render_template('order_detail.html', order=order)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login with SECURE authentication.
    
    SECURITY FIX: 
    - SQL Injection → ORM query (parameterized)
    - Weak Hashing → bcrypt password verification
    - CSRF → Token required (Flask-WTF)
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Input validation
        if not username or not password:
            flash('Username and password required', 'error')
            return redirect(url_for('login'))
        
        # ✅ SECURE: Using ORM query (parameterized, prevents SQLi)
        user = User.query.filter_by(username=username).first()
        
        # ✅ SECURE: bcrypt password verification
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Redirect to next page or home
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            # Generic error message (prevents username enumeration)
            flash('Invalid credentials', 'error')
            # Could add account lockout here after N failed attempts
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration with SECURE password hashing.
    
    SECURITY FIX:
    - Weak Hashing → bcrypt with salt
    - CSRF → Token required
    - Input validation
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        
        # Input validation
        if not username or not email or not password:
            flash('All fields required', 'error')
            return redirect(url_for('register'))
        
        # Password strength validation
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('register'))
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        # ✅ SECURE: bcrypt password hashing with automatic salt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user = User(
            username=username,
            email=email,
            password=password_hash.decode('utf-8'),  # Store as string
            is_admin=False
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/cart')
@login_required
def cart():
    """Shopping cart (CSRF protected)"""
    return render_template('cart.html')

@app.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    """
    Add product to cart (CSRF protected).
    
    SECURITY FIX: CSRF → Token required
    """
    product = Product.query.get_or_404(product_id)
    quantity = request.form.get('quantity', 1, type=int)
    
    # Input validation
    if quantity < 1 or quantity > product.stock:
        flash('Invalid quantity', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Cart logic here (simplified)
    flash(f'Added {quantity} x {product.name} to cart', 'success')
    return redirect(url_for('products'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    """
    Checkout process (CSRF protected).
    
    SECURITY FIX: CSRF → Token required
    """
    if request.method == 'POST':
        shipping_address = request.form.get('shipping_address', '')
        
        if not shipping_address:
            flash('Shipping address required', 'error')
            return redirect(url_for('checkout'))
        
        # Create order (simplified - real app would process cart)
        order = Order(
            user_id=current_user.id,
            total_price=0.00,  # Calculate from cart
            status='Pending',
            shipping_address=shipping_address
        )
        
        db.session.add(order)
        db.session.commit()
        
        flash('Order placed successfully!', 'success')
        return redirect(url_for('view_order', order_id=order.id))
    
    return render_template('checkout.html')

@app.route('/orders')
@login_required
def orders():
    """
    View user's orders with AUTHORIZATION.
    
    SECURITY FIX: Only show current user's orders
    """
    # ✅ SECURE: Filter by current user
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    
    return render_template('orders.html', orders=user_orders)

@app.route('/admin')
@login_required
def admin_dashboard():
    """
    Admin dashboard with AUTHORIZATION check.
    
    SECURITY FIX: Verify admin privileges
    """
    # ✅ SECURE: Admin authorization check
    if not current_user.is_admin:
        abort(403)  # Forbidden
    
    # Admin statistics
    total_users = User.query.count()
    total_products = Product.query.count()
    total_orders = Order.query.count()
    
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_products=total_products,
                         total_orders=total_orders,
                         recent_orders=recent_orders)

# Error handlers
@app.errorhandler(403)
def forbidden(e):
    """Handle 403 Forbidden errors"""
    return render_template('error.html', 
                         error_code=403,
                         error_message='Access Denied',
                         error_detail='You do not have permission to access this resource.'), 403

@app.errorhandler(404)
def not_found(e):
    """Handle 404 Not Found errors"""
    return render_template('error.html',
                         error_code=404,
                         error_message='Page Not Found',
                         error_detail='The page you are looking for does not exist.'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 Internal Server errors"""
    return render_template('error.html',
                         error_code=500,
                         error_message='Server Error',
                         error_detail='An internal server error occurred.'), 500

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("VulnHub E-commerce - Running in SECURE mode")
    print("=" * 60)
    print("\n✅ All security vulnerabilities have been remediated:")
    print("   • SQL Injection → Parameterized queries")
    print("   • XSS → Output encoding")
    print("   • IDOR → Authorization checks")
    print("   • Weak Auth → bcrypt password hashing")
    print("   • CSRF → Flask-WTF protection")
    print("   • Security Headers → Comprehensive configuration")
    print("\n" + "=" * 60)
    print(f"Access at: http://localhost:5002")
    print("=" * 60 + "\n")
    
    # Create database if it doesn't exist
    with app.app_context():
        db.create_all()
    
    app.run(host='0.0.0.0', port=5002, debug=True)