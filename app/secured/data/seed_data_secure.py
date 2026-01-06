#!/usr/bin/env python3
"""
Seed data for SECURE VulnHub E-commerce database
Uses bcrypt for password hashing

IMPORTANT: Run from VulnHub root directory!
python app/secured/data/seed_data_secure.py
"""

import sys
import os

# Add TWO levels up (app/) to Python path
# From: app/secured/data/seed_data_secure.py
# Up 2: app/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import from models.py in app/ directory
from models import db, User, Product, Order, Review

from flask import Flask
import bcrypt
from datetime import datetime, timedelta

# Initialize Flask with correct paths (relative to app/secured/data/)
app = Flask(__name__,
            template_folder='../../templates',
            static_folder='../../static')

# Database path - use absolute path to ensure it's in app/secured/data/
script_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(script_dir, 'ecommerce_secure.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secure-secret-key-for-seeding'

db.init_app(app)

def seed_database():
    """Seed the secure database with test data"""
    
    print("Seeding SECURE database with test data...")
    print("=" * 60)
    
    with app.app_context():
        # Create tables
        print("\n[1] Creating database tables...")
        db.create_all()
        print("    ✓ Tables created")
        
        # Clear existing data
        print("\n[2] Clearing existing data...")
        Review.query.delete()
        Order.query.delete()
        Product.query.delete()
        User.query.delete()
        db.session.commit()
        print("    ✓ Existing data cleared")
        
        # Create users with BCRYPT hashing
        print("\n[3] Creating users with bcrypt password hashing...")
        
        users_data = [
            {
                'username': 'admin',
                'password': 'admin123',
                'email': 'admin@vulnhub.local',
                'is_admin': True
            },
            {
                'username': 'user',
                'password': 'password',
                'email': 'user@vulnhub.local',
                'is_admin': False
            },
            {
                'username': 'alice',
                'password': 'alice',
                'email': 'alice@vulnhub.local',
                'is_admin': False
            },
            {
                'username': 'bob',
                'password': 'bob',
                'email': 'bob@vulnhub.local',
                'is_admin': False
            },
            {
                'username': 'charlie',
                'password': 'charlie',
                'email': 'charlie@vulnhub.local',
                'is_admin': False
            }
        ]
        
        users = []
        for user_data in users_data:
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(
                user_data['password'].encode('utf-8'),
                bcrypt.gensalt()
            )
            
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password=password_hash.decode('utf-8'),
                is_admin=user_data['is_admin']
            )
            users.append(user)
            db.session.add(user)
            
            print(f"    ✓ Created user: {user_data['username']} (bcrypt hash)")
        
        db.session.commit()
        
        # Create products
        print("\n[4] Creating products...")
        
        products_data = [
            {
                'name': 'Laptop Pro 15',
                'description': 'High-performance laptop with 16GB RAM',
                'price': 1299.99,
                'stock': 10,
                'category': 'Electronics',
                'image_url': 'https://via.placeholder.com/300x300?text=Laptop'
            },
            {
                'name': 'Smartphone X',
                'description': 'Latest smartphone with 5G capability',
                'price': 899.99,
                'stock': 25,
                'category': 'Electronics',
                'image_url': 'https://via.placeholder.com/300x300?text=Phone'
            },
            {
                'name': 'Wireless Headphones',
                'description': 'Noise-cancelling bluetooth headphones',
                'price': 199.99,
                'stock': 50,
                'category': 'Electronics',
                'image_url': 'https://via.placeholder.com/300x300?text=Headphones'
            },
            {
                'name': 'Running Shoes',
                'description': 'Comfortable athletic shoes',
                'price': 89.99,
                'stock': 100,
                'category': 'Sports',
                'image_url': 'https://via.placeholder.com/300x300?text=Shoes'
            },
            {
                'name': 'Yoga Mat',
                'description': 'Premium non-slip yoga mat',
                'price': 29.99,
                'stock': 75,
                'category': 'Sports',
                'image_url': 'https://via.placeholder.com/300x300?text=Yoga+Mat'
            },
            {
                'name': 'Coffee Maker',
                'description': 'Programmable coffee maker with timer',
                'price': 79.99,
                'stock': 30,
                'category': 'Home & Garden',
                'image_url': 'https://via.placeholder.com/300x300?text=Coffee+Maker'
            },
            {
                'name': 'Python Programming Book',
                'description': 'Learn Python from scratch',
                'price': 39.99,
                'stock': 50,
                'category': 'Books',
                'image_url': 'https://via.placeholder.com/300x300?text=Python+Book'
            },
            {
                'name': 'Gaming Mouse',
                'description': 'RGB gaming mouse with 16000 DPI',
                'price': 59.99,
                'stock': 40,
                'category': 'Electronics',
                'image_url': 'https://via.placeholder.com/300x300?text=Gaming+Mouse'
            },
            {
                'name': 'Backpack',
                'description': 'Water-resistant laptop backpack',
                'price': 49.99,
                'stock': 60,
                'category': 'Clothing',
                'image_url': 'https://via.placeholder.com/300x300?text=Backpack'
            },
            {
                'name': 'Water Bottle',
                'description': 'Insulated stainless steel water bottle',
                'price': 24.99,
                'stock': 100,
                'category': 'Sports',
                'image_url': 'https://via.placeholder.com/300x300?text=Water+Bottle'
            }
        ]
        
        products = []
        for product_data in products_data:
            product = Product(**product_data)
            products.append(product)
            db.session.add(product)
            print(f"    ✓ Created product: {product_data['name']}")
        
        db.session.commit()
        
        # Create orders
        print("\n[5] Creating orders...")
        
        orders_data = [
            {
                'user': users[2],  # alice
                'total_price': 1299.99,
                'status': 'Delivered',
                'shipping_address': '123 Main St, Anytown, USA',
                'created_at': datetime.utcnow() - timedelta(days=5)
            },
            {
                'user': users[3],  # bob
                'total_price': 19.99,
                'status': 'Shipped',
                'shipping_address': '456 Oak Ave, Springfield, USA',
                'created_at': datetime.utcnow() - timedelta(days=2)
            },
            {
                'user': users[1],  # user
                'total_price': 29.99,
                'status': 'Pending',
                'shipping_address': '789 Elm St, Riverside, USA',
                'created_at': datetime.utcnow() - timedelta(days=1)
            },
            {
                'user': users[4],  # charlie
                'total_price': 149.97,
                'status': 'Processing',
                'shipping_address': '321 Pine Rd, Lakeside, USA',
                'created_at': datetime.utcnow()
            }
        ]
        
        for order_data in orders_data:
            order = Order(
                user_id=order_data['user'].id,
                total_price=order_data['total_price'],
                status=order_data['status'],
                shipping_address=order_data['shipping_address'],
                created_at=order_data['created_at']
            )
            db.session.add(order)
            print(f"    ✓ Created order for {order_data['user'].username}: ${order_data['total_price']}")
        
        db.session.commit()
        
        # Create reviews
        print("\n[6] Creating reviews...")
        
        reviews_data = [
            {
                'product': products[0],
                'user': users[1],
                'rating': 5,
                'comment': 'Excellent laptop! Very fast and reliable.'
            },
            {
                'product': products[1],
                'user': users[2],
                'rating': 4,
                'comment': 'Great phone, battery could be better.'
            },
            {
                'product': products[2],
                'user': users[3],
                'rating': 5,
                'comment': 'Best headphones I\'ve ever owned!'
            },
            {
                'product': products[0],
                'user': users[4],
                'rating': 4,
                'comment': 'Good performance, a bit expensive though.'
            }
        ]
        
        for review_data in reviews_data:
            review = Review(
                product_id=review_data['product'].id,
                user_id=review_data['user'].id,
                rating=review_data['rating'],
                comment=review_data['comment']
            )
            db.session.add(review)
            print(f"    ✓ Created review by {review_data['user'].username} for {review_data['product'].name}")
        
        db.session.commit()
        
        print("\n" + "=" * 60)
        print("✅ SECURE database seeded successfully!")
        print("=" * 60)
        print("\nDatabase contents:")
        print(f"  Users:    {User.query.count()}")
        print(f"  Products: {Product.query.count()}")
        print(f"  Orders:   {Order.query.count()}")
        print(f"  Reviews:  {Review.query.count()}")
        print("\nTest credentials (with bcrypt hashing):")
        print("  admin/admin123   (Administrator)")
        print("  user/password    (Regular user)")
        print("  alice/alice      (Regular user)")
        print("  bob/bob          (Regular user)")
        print("  charlie/charlie  (Regular user)")
        print("\nDatabase location:")
        print("  app/secured/data/ecommerce_secure.db")
        print("\nRun secure application:")
        print("  python app/secured/app_secure.py")
        print("=" * 60)

if __name__ == '__main__':
    seed_database()