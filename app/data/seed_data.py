import sys
import os

# Add parent directory to path so we can import app modules
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, parent_dir)

# Now import from app
from app.app import app, db
from app.models import User, Product, Order, OrderItem, Review
import hashlib


def hash_password_weak(password):
    """Weak password hashing using MD5 (intentionally vulnerable)"""
    return hashlib.md5(password.encode()).hexdigest()


def seed_users():
    """Create sample users"""
    print("[*] Seeding users...")
    
    users = [
        {
            'username': 'admin',
            'email': 'admin@vulnhub.com',
            'password': hash_password_weak('admin123'),
            'is_admin': True
        },
        {
            'username': 'user',
            'email': 'user@vulnhub.com',
            'password': hash_password_weak('password'),
            'is_admin': False
        },
        {
            'username': 'alice',
            'email': 'alice@example.com',
            'password': hash_password_weak('alice123'),
            'is_admin': False
        },
        {
            'username': 'bob',
            'email': 'bob@example.com',
            'password': hash_password_weak('bob123'),
            'is_admin': False
        },
        {
            'username': 'charlie',
            'email': 'charlie@example.com',
            'password': hash_password_weak('charlie123'),
            'is_admin': False
        }
    ]
    
    for user_data in users:
        existing = User.query.filter_by(username=user_data['username']).first()
        if not existing:
            user = User(**user_data)
            db.session.add(user)
            print(f"  [+] Created user: {user_data['username']}")
        else:
            print(f"  [-] User already exists: {user_data['username']}")
    
    db.session.commit()
    print("[+] Users seeded successfully!\n")


def seed_products():
    """Create sample products across different categories"""
    print("[*] Seeding products...")
    
    products = [
        # Electronics
        {
            'name': 'Laptop Pro 15"',
            'description': 'High-performance laptop with 16GB RAM and 512GB SSD',
            'price': 1299.99,
            'stock': 25,
            'category': 'Electronics',
            'image_url': 'https://picsum.photos/seed/laptop/400/300'
        },
        {
            'name': 'Wireless Mouse',
            'description': 'Ergonomic wireless mouse with precision tracking',
            'price': 29.99,
            'stock': 150,
            'category': 'Electronics',
            'image_url': 'https://picsum.photos/seed/mouse/400/300'
        },
        {
            'name': 'USB-C Hub',
            'description': '7-in-1 USB-C hub with HDMI and ethernet ports',
            'price': 49.99,
            'stock': 80,
            'category': 'Electronics',
            'image_url': 'https://picsum.photos/seed/usbhub/400/300'
        },
        {
            'name': 'Mechanical Keyboard',
            'description': 'RGB mechanical keyboard with blue switches',
            'price': 89.99,
            'stock': 60,
            'category': 'Electronics',
            'image_url': 'https://picsum.photos/seed/keyboard/400/300'
        },
        {
            'name': '27" 4K Monitor',
            'description': 'Ultra HD monitor with HDR support',
            'price': 399.99,
            'stock': 35,
            'category': 'Electronics',
            'image_url': 'https://picsum.photos/seed/monitor/400/300'
        },

        # Clothing
        {
            'name': 'Cotton T-Shirt',
            'description': 'Comfortable 100% cotton t-shirt in various colors',
            'price': 19.99,
            'stock': 200,
            'category': 'Clothing',
            'image_url': 'https://picsum.photos/seed/tshirt/400/300'
        },
        {
            'name': 'Denim Jeans',
            'description': 'Classic fit denim jeans',
            'price': 59.99,
            'stock': 120,
            'category': 'Clothing',
            'image_url': 'https://picsum.photos/seed/jeans/400/300'
        },
        {
            'name': 'Running Shoes',
            'description': 'Lightweight running shoes with cushioned sole',
            'price': 79.99,
            'stock': 90,
            'category': 'Clothing',
            'image_url': 'https://picsum.photos/seed/shoes/400/300'
        },
        {
            'name': 'Hoodie',
            'description': 'Warm fleece hoodie with front pocket',
            'price': 44.99,
            'stock': 75,
            'category': 'Clothing',
            'image_url': 'https://picsum.photos/seed/hoodie/400/300'
        },

        # Books
        {
            'name': 'Web Security for Developers',
            'description': 'Comprehensive guide to web application security',
            'price': 39.99,
            'stock': 50,
            'category': 'Books',
            'image_url': 'https://picsum.photos/seed/security-book/400/300'
        },
        {
            'name': 'Python for Hackers',
            'description': 'Learn Python for penetration testing',
            'price': 44.99,
            'stock': 65,
            'category': 'Books',
            'image_url': 'https://picsum.photos/seed/python-book/400/300'
        },
        {
            'name': 'The Art of Exploitation',
            'description': 'Deep dive into software exploitation',
            'price': 49.99,
            'stock': 40,
            'category': 'Books',
            'image_url': 'https://picsum.photos/seed/exploit-book/400/300'
        },

        # Home
        {
            'name': 'Coffee Maker',
            'description': 'Programmable coffee maker with thermal carafe',
            'price': 89.99,
            'stock': 45,
            'category': 'Home',
            'image_url': 'https://picsum.photos/seed/coffee/400/300'
        },
        {
            'name': 'Desk Lamp',
            'description': 'LED desk lamp with adjustable brightness',
            'price': 34.99,
            'stock': 100,
            'category': 'Home',
            'image_url': 'https://picsum.photos/seed/lamp/400/300'
        },
        {
            'name': 'Standing Desk',
            'description': 'Electric height-adjustable standing desk',
            'price': 499.99,
            'stock': 20,
            'category': 'Home',
            'image_url': 'https://picsum.photos/seed/desk/400/300'
        },

        # Sports
        {
            'name': 'Yoga Mat',
            'description': 'Non-slip yoga mat with carrying strap',
            'price': 29.99,
            'stock': 85,
            'category': 'Sports',
            'image_url': 'https://picsum.photos/seed/yoga/400/300'
        },
        {
            'name': 'Dumbbell Set',
            'description': 'Adjustable dumbbell set 5-50 lbs',
            'price': 199.99,
            'stock': 30,
            'category': 'Sports',
            'image_url': 'https://picsum.photos/seed/dumbbells/400/300'
        },
        {
            'name': 'Resistance Bands',
            'description': 'Set of 5 resistance bands for strength training',
            'price': 24.99,
            'stock': 120,
            'category': 'Sports',
            'image_url': 'https://picsum.photos/seed/bands/400/300'
        },
        {
            'name': 'Water Bottle',
            'description': 'Insulated stainless steel water bottle',
            'price': 19.99,
            'stock': 150,
            'category': 'Sports',
            'image_url': 'https://picsum.photos/seed/bottle/400/300'
        },
        {
            'name': 'Fitness Tracker',
            'description': 'Smart fitness tracker with heart rate monitor',
            'price': 129.99,
            'stock': 55,
            'category': 'Sports',
            'image_url': 'https://picsum.photos/seed/tracker/400/300'
        }
    ]
    
    for product_data in products:
        existing = Product.query.filter_by(name=product_data['name']).first()
        if not existing:
            product = Product(**product_data)
            db.session.add(product)
            print(f"  [+] Created product: {product_data['name']}")
        else:
            print(f"  [-] Product already exists: {product_data['name']}")
    
    db.session.commit()
    print("[+] Products seeded successfully!\n")


def seed_orders():
    """Create sample orders"""
    print("[*] Seeding orders...")
    
    # Get users
    alice = User.query.filter_by(username='alice').first()
    bob = User.query.filter_by(username='bob').first()
    user = User.query.filter_by(username='user').first()
    
    # Get some products
    laptop = Product.query.filter_by(name='Laptop Pro 15"').first()
    mouse = Product.query.filter_by(name='Wireless Mouse').first()
    tshirt = Product.query.filter_by(name='Cotton T-Shirt').first()
    book = Product.query.filter_by(name='Web Security for Developers').first()
    
    if not all([alice, bob, user, laptop, mouse, tshirt, book]):
        print("  [!] Missing required users or products, skipping orders")
        return
    
    orders_data = [
        {
            'user': alice,
            'items': [
                {'product': laptop, 'quantity': 1, 'price': laptop.price},
                {'product': mouse, 'quantity': 2, 'price': mouse.price}
            ],
            'status': 'delivered',
            'shipping_address': '123 Main St, New York, NY 10001'
        },
        {
            'user': bob,
            'items': [
                {'product': tshirt, 'quantity': 3, 'price': tshirt.price},
                {'product': book, 'quantity': 1, 'price': book.price}
            ],
            'status': 'shipped',
            'shipping_address': '456 Oak Ave, Brooklyn, NY 11201'
        },
        {
            'user': user,
            'items': [
                {'product': mouse, 'quantity': 1, 'price': mouse.price}
            ],
            'status': 'pending',
            'shipping_address': '789 Pine St, Queens, NY 11354'
        }
    ]
    
    for order_data in orders_data:
        # Calculate total
        total = sum(item['price'] * item['quantity'] for item in order_data['items'])
        
        # Create order
        order = Order(
            user_id=order_data['user'].id,
            total_price=total,
            status=order_data['status'],
            shipping_address=order_data['shipping_address']
        )
        db.session.add(order)
        db.session.flush()  # Get order ID
        
        # Create order items
        for item_data in order_data['items']:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item_data['product'].id,
                quantity=item_data['quantity'],
                price=item_data['price']
            )
            db.session.add(order_item)
        
        print(f"  [+] Created order for {order_data['user'].username}")
    
    db.session.commit()
    print("[+] Orders seeded successfully!\n")


def seed_reviews():
    """Create sample reviews (including XSS payloads for testing)"""
    print("[*] Seeding reviews...")
    
    # Get users and products
    alice = User.query.filter_by(username='alice').first()
    bob = User.query.filter_by(username='bob').first()
    user = User.query.filter_by(username='user').first()
    
    laptop = Product.query.filter_by(name='Laptop Pro 15"').first()
    mouse = Product.query.filter_by(name='Wireless Mouse').first()
    book = Product.query.filter_by(name='Web Security for Developers').first()
    
    if not all([alice, bob, user, laptop, mouse, book]):
        print("  [!] Missing required users or products, skipping reviews")
        return
    
    reviews_data = [
        # Normal reviews
        {
            'product': laptop,
            'user': alice,
            'rating': 5,
            'comment': 'Excellent laptop! Very fast and reliable.'
        },
        {
            'product': mouse,
            'user': bob,
            'rating': 4,
            'comment': 'Good mouse, comfortable to use. Battery life is great.'
        },
        {
            'product': book,
            'user': user,
            'rating': 5,
            'comment': 'Must-read for any web developer. Very comprehensive!'
        },
        
        # XSS payload reviews (for testing vulnerability)
        {
            'product': laptop,
            'user': bob,
            'rating': 5,
            'comment': '<script>alert("XSS")</script>Great product!'
        },
        {
            'product': mouse,
            'user': alice,
            'rating': 3,
            'comment': '<img src=x onerror=alert("XSS")>Nice mouse'
        },
        {
            'product': book,
            'user': bob,
            'rating': 4,
            'comment': '<svg onload=alert("XSS")></svg>Informative book'
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
        print(f"  [+] Created review for {review_data['product'].name}")
    
    db.session.commit()
    print("[+] Reviews seeded successfully!\n")


def seed_all():
    """Seed entire database"""
    print("\n" + "="*60)
    print("VulnHub E-commerce - Database Seeding")
    print("="*60 + "\n")
    
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Seed data
        seed_users()
        seed_products()
        seed_orders()
        seed_reviews()
        
        print("="*60)
        print("Database seeding complete!")
        print("="*60)
        print("\nDefault Credentials:")
        print("  Admin: admin / admin123")
        print("  User:  user / password")
        print("  Alice: alice / alice123")
        print("  Bob:   bob / bob123")
        print("  Charlie: charlie / charlie123")
        print("\nNote: Passwords are hashed with MD5 (intentionally weak)")
        print("="*60 + "\n")


if __name__ == '__main__':
    seed_all()