import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = 'recipe_app.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db_connection()
    
    # Users table with enhanced fields
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT,
            avatar_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Recipes table with image and category
    conn.execute('''
        CREATE TABLE IF NOT EXISTS recipes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            ingredients TEXT NOT NULL,
            instructions TEXT NOT NULL,
            image_url TEXT,
            category TEXT,
            prep_time INTEGER,
            cook_time INTEGER,
            servings INTEGER,
            difficulty TEXT,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Comments table - XSS VULNERABILITY POINT
    conn.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            recipe_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (recipe_id) REFERENCES recipes (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Ratings table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
            recipe_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(recipe_id, user_id),
            FOREIGN KEY (recipe_id) REFERENCES recipes (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Favorites table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(recipe_id, user_id),
            FOREIGN KEY (recipe_id) REFERENCES recipes (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    
    # Add sample data with hashed passwords
    try:
        conn.execute('''INSERT INTO users (username, email, password, bio) VALUES (?, ?, ?, ?)''', 
                     ('chef_anna', 'anna@example.com', 
                      generate_password_hash('password123'), 
                      'Passionate home cook sharing family recipes!'))
        
        conn.execute('''INSERT INTO users (username, email, password, bio) VALUES (?, ?, ?, ?)''', 
                     ('baker_bob', 'bob@example.com', 
                      generate_password_hash('password123'),
                      'Professional baker with 15 years experience.'))
        
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Users already exist
    
    # Add sample recipes (only if they don't exist)
    user1 = conn.execute('SELECT id FROM users WHERE username = ?', ('chef_anna',)).fetchone()
    user2 = conn.execute('SELECT id FROM users WHERE username = ?', ('baker_bob',)).fetchone()
    
    # Check if recipes already exist
    existing_recipes = conn.execute('SELECT COUNT(*) as count FROM recipes').fetchone()
    
    if user1 and existing_recipes['count'] == 0:
        try:
            conn.execute('''INSERT INTO recipes 
                (title, description, ingredients, instructions, category, prep_time, cook_time, servings, difficulty, user_id, image_url) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                ('Chocolate Chip Cookies', 
                 'Delicious homemade cookies with gooey chocolate chips. Perfect for any occasion!',
                 '2 cups all-purpose flour\n1 cup butter, softened\n3/4 cup sugar\n3/4 cup brown sugar\n2 eggs\n2 tsp vanilla extract\n1 tsp baking soda\n1 tsp salt\n2 cups chocolate chips',
                 '1. Preheat oven to 350°F (175°C)\n2. Cream together butter and sugars until fluffy\n3. Beat in eggs and vanilla\n4. In separate bowl, mix flour, baking soda, and salt\n5. Gradually blend dry ingredients into butter mixture\n6. Stir in chocolate chips\n7. Drop rounded tablespoons onto ungreased cookie sheets\n8. Bake for 10-12 minutes or until golden brown',
                 'Desserts',
                 15, 12, 24, 'Easy',
                 user1['id'],
                 'https://images.unsplash.com/photo-1499636136210-6f4ee915583e?w=400'))
            
            conn.execute('''INSERT INTO recipes 
                (title, description, ingredients, instructions, category, prep_time, cook_time, servings, difficulty, user_id, image_url) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                ('Classic Spaghetti Carbonara',
                 'Authentic Italian pasta dish with a creamy egg sauce, crispy pancetta, and parmesan.',
                 '400g spaghetti\n200g pancetta or guanciale\n4 large eggs\n100g Pecorino Romano cheese, grated\n100g Parmesan cheese, grated\nBlack pepper\nSalt',
                 '1. Cook spaghetti in salted boiling water until al dente\n2. While pasta cooks, cut pancetta into small pieces and fry until crispy\n3. In a bowl, whisk eggs with grated cheeses and black pepper\n4. Drain pasta, reserving 1 cup pasta water\n5. Remove pan from heat, add pasta to pancetta\n6. Quickly stir in egg mixture, adding pasta water to create creamy sauce\n7. Serve immediately with extra cheese and black pepper',
                 'Main Course',
                 10, 15, 4, 'Medium',
                 user1['id'],
                 'https://images.unsplash.com/photo-1612874742237-6526221588e3?w=400'))
            
            conn.commit()
        except sqlite3.IntegrityError:
            pass
    
    if user2 and existing_recipes['count'] == 0:
        try:
            conn.execute('''INSERT INTO recipes 
                (title, description, ingredients, instructions, category, prep_time, cook_time, servings, difficulty, user_id, image_url) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                ('Homemade Sourdough Bread',
                 'Artisan sourdough bread with a crispy crust and soft, tangy interior. Worth the wait!',
                 '500g bread flour\n350ml water\n100g active sourdough starter\n10g salt',
                 '1. Mix flour and water, let rest 30 minutes (autolyse)\n2. Add starter and salt, mix well\n3. Bulk fermentation for 4-6 hours with stretch and folds every 30 mins\n4. Shape into boule or batard\n5. Cold proof overnight in fridge (12-18 hours)\n6. Preheat Dutch oven to 450°F\n7. Score bread and bake covered for 20 mins\n8. Remove lid, bake 25-30 mins until deep golden brown',
                 'Bread',
                 30, 45, 1, 'Hard',
                 user2['id'],
                 'https://images.unsplash.com/photo-1549931319-a545dcf3bc73?w=400'))
            
            conn.commit()
        except sqlite3.IntegrityError:
            pass
    
    # Add sample comments - ONLY IF THEY DON'T EXIST
    existing_comments = conn.execute('SELECT COUNT(*) as count FROM comments').fetchone()
    
    if existing_comments['count'] == 0:
        recipe = conn.execute('SELECT id FROM recipes WHERE title = ?', ('Chocolate Chip Cookies',)).fetchone()
        if recipe and user2:
            try:
                conn.execute('''INSERT INTO comments (content, recipe_id, user_id) VALUES (?, ?, ?)''',
                            ('These cookies are absolutely delicious! My kids loved them!', recipe['id'], user2['id']))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
    
    conn.close()
    print("Database initialized successfully!")

if __name__ == '__main__':
    init_database()