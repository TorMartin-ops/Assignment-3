import sqlite3

DATABASE = 'recipe_app.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn



def init_database():
    conn = get_db_connection()
    
    # Users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Recipes table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS recipes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            ingredients TEXT NOT NULL,
            instructions TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Comments table - THIS IS WHERE XSS VULNERABILITY WILL BE
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
    
    conn.commit()
    conn.close()
    
    # Add sample data
    conn = get_db_connection()
    conn.execute('''INSERT OR IGNORE INTO users (username, email, password) VALUES (?, ?, ?)''', 
                 ('testuser', 'test@example.com', 'password123'))
    
    user_result = conn.execute('SELECT id FROM users WHERE username = ?', ('testuser',)).fetchone()
    if user_result:
        conn.execute('''INSERT OR IGNORE INTO recipes (title, description, ingredients, instructions, user_id) VALUES (?, ?, ?, ?, ?)''', 
                     ('Chocolate Chip Cookies', 'Delicious homemade cookies perfect for any occasion!', 
                      '2 cups flour, 1 cup butter, 1/2 cup sugar, 1 cup chocolate chips, 2 eggs', 
                      '1. Mix dry ingredients. 2. Cream butter and sugar. 3. Add eggs. 4. Combine all. 5. Bake at 350°F for 12 minutes.', 
                      user_result['id']))
        
        # Add sample safe comment
        recipe_result = conn.execute('SELECT id FROM recipes WHERE title = ?', ('Chocolate Chip Cookies',)).fetchone()
        if recipe_result:
            conn.execute('''INSERT OR IGNORE INTO comments (content, recipe_id, user_id) VALUES (?, ?, ?)''',
                        ('This recipe is amazing! Thanks for sharing.', recipe_result['id'], user_result['id']))
    
    conn.commit()
    conn.close()
    print("Database setup complete!")