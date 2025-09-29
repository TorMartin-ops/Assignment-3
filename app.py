from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection, init_database
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Initialize database on startup
init_database()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    """Home page with search and filter"""
    conn = get_db_connection()
    
    # Get search and filter parameters
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    difficulty = request.args.get('difficulty', '')
    
    # Build query with filters
    query = '''
        SELECT r.*, u.username,
               COALESCE(AVG(rt.rating), 0) as avg_rating,
               COUNT(DISTINCT rt.id) as rating_count
        FROM recipes r 
        JOIN users u ON r.user_id = u.id 
        LEFT JOIN ratings rt ON r.id = rt.recipe_id
        WHERE 1=1
    '''
    params = []
    
    if search:
        query += ' AND (r.title LIKE ? OR r.description LIKE ? OR r.ingredients LIKE ?)'
        search_param = f'%{search}%'
        params.extend([search_param, search_param, search_param])
    
    if category:
        query += ' AND r.category = ?'
        params.append(category)
    
    if difficulty:
        query += ' AND r.difficulty = ?'
        params.append(difficulty)
    
    query += ' GROUP BY r.id ORDER BY r.created_at DESC'
    
    recipes = conn.execute(query, params).fetchall()
    
    # Get categories for filter
    categories = conn.execute('SELECT DISTINCT category FROM recipes WHERE category IS NOT NULL').fetchall()
    
    conn.close()
    return render_template('home.html', 
                         recipes=recipes, 
                         categories=categories,
                         search=search,
                         current_category=category,
                         current_difficulty=difficulty)

@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    """Show recipe with XSS vulnerability in comments"""
    conn = get_db_connection()
    
    # Get recipe with rating
    recipe = conn.execute('''
        SELECT r.*, u.username, u.id as author_id,
               COALESCE(AVG(rt.rating), 0) as avg_rating,
               COUNT(DISTINCT rt.id) as rating_count
        FROM recipes r 
        JOIN users u ON r.user_id = u.id 
        LEFT JOIN ratings rt ON r.id = rt.recipe_id
        WHERE r.id = ?
        GROUP BY r.id
    ''', (recipe_id,)).fetchone()
    
    if not recipe:
        flash('Recipe not found!', 'danger')
        return redirect(url_for('home'))
    
    # Get comments - XSS VULNERABILITY HERE
    comments = conn.execute('''
        SELECT c.*, u.username 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.recipe_id = ? 
        ORDER BY c.created_at DESC
    ''', (recipe_id,)).fetchall()
    
    # Check if user has rated this recipe
    user_rating = None
    is_favorited = False
    if 'user_id' in session:
        rating_result = conn.execute(
            'SELECT rating FROM ratings WHERE recipe_id = ? AND user_id = ?',
            (recipe_id, session['user_id'])
        ).fetchone()
        if rating_result:
            user_rating = rating_result['rating']
        
        # Check if favorited
        fav_result = conn.execute(
            'SELECT id FROM favorites WHERE recipe_id = ? AND user_id = ?',
            (recipe_id, session['user_id'])
        ).fetchone()
        is_favorited = fav_result is not None
    
    conn.close()
    return render_template('recipe_detail.html', 
                         recipe=recipe, 
                         comments=comments,
                         user_rating=user_rating,
                         is_favorited=is_favorited)

@app.route('/add_comment/<int:recipe_id>', methods=['POST'])
@login_required
def add_comment(recipe_id):
    """Add comment - XSS VULNERABILITY ENTRY POINT"""
    content = request.form.get('content')
    if not content:
        flash('Comment cannot be empty!', 'warning')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))
    
    # Store WITHOUT sanitization - INTENTIONAL VULNERABILITY
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO comments (content, recipe_id, user_id)
        VALUES (?, ?, ?)
    ''', (content, recipe_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Comment added!', 'success')
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

@app.route('/rate/<int:recipe_id>', methods=['POST'])
@login_required
def rate_recipe(recipe_id):
    """Rate a recipe"""
    rating = request.form.get('rating', type=int)
    if not rating or rating < 1 or rating > 5:
        flash('Invalid rating!', 'danger')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))
    
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO ratings (rating, recipe_id, user_id)
            VALUES (?, ?, ?)
            ON CONFLICT(recipe_id, user_id) DO UPDATE SET rating = ?
        ''', (rating, recipe_id, session['user_id'], rating))
        conn.commit()
        flash(f'Rating of {rating} stars added!', 'success')
    except Exception as e:
        flash('Error adding rating!', 'danger')
    conn.close()
    
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

@app.route('/favorite/<int:recipe_id>', methods=['POST'])
@login_required
def toggle_favorite(recipe_id):
    """Add/remove recipe from favorites"""
    conn = get_db_connection()
    
    existing = conn.execute(
        'SELECT id FROM favorites WHERE recipe_id = ? AND user_id = ?',
        (recipe_id, session['user_id'])
    ).fetchone()
    
    if existing:
        conn.execute('DELETE FROM favorites WHERE recipe_id = ? AND user_id = ?',
                    (recipe_id, session['user_id']))
        flash('Removed from favorites!', 'info')
    else:
        conn.execute('INSERT INTO favorites (recipe_id, user_id) VALUES (?, ?)',
                    (recipe_id, session['user_id']))
        flash('Added to favorites!', 'success')
    
    conn.commit()
    conn.close()
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        conn = get_db_connection()
        
        # Check if user exists
        existing = conn.execute('SELECT id FROM users WHERE username = ? OR email = ?',
                              (username, email)).fetchone()
        if existing:
            flash('Username or email already exists!', 'danger')
            conn.close()
            return redirect(url_for('register'))
        
        # Create user
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                    (username, email, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile/<username>')
def profile(username):
    """User profile page"""
    conn = get_db_connection()
    
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        flash('User not found!', 'danger')
        conn.close()
        return redirect(url_for('home'))
    
    # Get user's recipes
    recipes = conn.execute('''
        SELECT r.*, 
               COALESCE(AVG(rt.rating), 0) as avg_rating,
               COUNT(DISTINCT rt.id) as rating_count
        FROM recipes r
        LEFT JOIN ratings rt ON r.id = rt.recipe_id
        WHERE r.user_id = ?
        GROUP BY r.id
        ORDER BY r.created_at DESC
    ''', (user['id'],)).fetchall()
    
    # Get user's favorites
    favorites = conn.execute('''
        SELECT r.*, u.username,
               COALESCE(AVG(rt.rating), 0) as avg_rating
        FROM favorites f
        JOIN recipes r ON f.recipe_id = r.id
        JOIN users u ON r.user_id = u.id
        LEFT JOIN ratings rt ON r.id = rt.recipe_id
        WHERE f.user_id = ?
        GROUP BY r.id
        ORDER BY f.created_at DESC
    ''', (user['id'],)).fetchall()
    
    conn.close()
    return render_template('profile.html', user=user, recipes=recipes, favorites=favorites)

@app.route('/add_recipe', methods=['GET', 'POST'])
@login_required
def add_recipe():
    """Add new recipe"""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        ingredients = request.form.get('ingredients')
        instructions = request.form.get('instructions')
        category = request.form.get('category')
        difficulty = request.form.get('difficulty')
        prep_time = request.form.get('prep_time', type=int)
        cook_time = request.form.get('cook_time', type=int)
        servings = request.form.get('servings', type=int)
        image_url = request.form.get('image_url')
        
        if not title or not description or not ingredients or not instructions:
            flash('Please fill in all required fields!', 'danger')
            return redirect(url_for('add_recipe'))
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO recipes 
            (title, description, ingredients, instructions, category, difficulty, 
             prep_time, cook_time, servings, image_url, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, description, ingredients, instructions, category, difficulty,
              prep_time, cook_time, servings, image_url, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Recipe added successfully!', 'success')
        return redirect(url_for('home'))
    
    return render_template('add_recipe.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)