from flask import Flask, render_template, request, redirect, url_for
from database import get_db_connection, init_database

# Create the Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Initialize database on startup
init_database()

@app.route('/')
def home():
    """Home page showing all recipes"""
    conn = get_db_connection()
    recipes = conn.execute('''
        SELECT r.*, u.username 
        FROM recipes r 
        JOIN users u ON r.user_id = u.id 
        ORDER BY r.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('home.html', recipes=recipes)

@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    """Show individual recipe with comments - XSS VULNERABILITY POINT"""
    conn = get_db_connection()
    
    # Get recipe details
    recipe = conn.execute('''
        SELECT r.*, u.username 
        FROM recipes r 
        JOIN users u ON r.user_id = u.id 
        WHERE r.id = ?
    ''', (recipe_id,)).fetchone()
    
    if not recipe:
        return "Recipe not found!", 404
    
    # Get comments for this recipe
    try:
        comments = conn.execute('''
            SELECT c.*, u.username 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.recipe_id = ? 
            ORDER BY c.created_at DESC
        ''', (recipe_id,)).fetchall()
    except:
        comments = []
    
    conn.close()
    return render_template('recipe_detail.html', recipe=recipe, comments=comments)

@app.route('/add_comment/<int:recipe_id>', methods=['POST'])
def add_comment(recipe_id):
    """Add comment - THIS IS THE XSS VULNERABILITY ENTRY POINT"""
    content = request.form.get('content')
    if not content:
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))
    
    # Store comment WITHOUT sanitization - INTENTIONAL VULNERABILITY
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO comments (content, recipe_id, user_id)
            VALUES (?, ?, ?)
        ''', (content, recipe_id, 1))
        conn.commit()
    except:
        pass
    conn.close()
    
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

if __name__ == '__main__':
    app.run(debug=True)