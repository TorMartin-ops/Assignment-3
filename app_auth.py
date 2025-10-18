"""
Authentication System - Main Application
OAuth2 + 2FA + Brute Force Protection + Secure Authentication

This is a complete authentication system implementation for Assignment 2
Run this instead of app.py to use the new authentication features
"""
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from database import get_db_connection, init_database
from database_auth import initialize_auth_database
from routes import auth_bp, oauth_bp, twofa_bp
from utils import login_required, set_security_headers, sanitize_comment, get_recaptcha_service
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Initialize databases
init_database()  # Original recipe database
initialize_auth_database()  # New auth tables

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(oauth_bp)
app.register_blueprint(twofa_bp)

# Initialize reCAPTCHA
recaptcha_service = get_recaptcha_service()

# Make reCAPTCHA site key available to all templates
@app.context_processor
def inject_recaptcha():
    """Inject reCAPTCHA site key into all templates"""
    return {
        'recaptcha_site_key': recaptcha_service.get_site_key(),
        'recaptcha_enabled': recaptcha_service.is_enabled()
    }

# Security headers
@app.after_request
def apply_security_headers(response):
    """Add security headers to all responses"""
    return set_security_headers(response)

# ============================================
# RECIPE APP ROUTES (from original app.py)
# ============================================

@app.route('/')
def home():
    """Home page with recipes"""
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
    """Recipe detail page"""
    conn = get_db_connection()

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
        flash('Recipe not found', 'danger')
        return redirect(url_for('home'))

    # Get comments
    comments = conn.execute('''
        SELECT c.*, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.recipe_id = ?
        ORDER BY c.created_at DESC
    ''', (recipe_id,)).fetchall()

    # Check user rating
    user_rating = None
    is_favorited = False
    if 'user_id' in session:
        rating_result = conn.execute(
            'SELECT rating FROM ratings WHERE recipe_id = ? AND user_id = ?',
            (recipe_id, session['user_id'])
        ).fetchone()
        if rating_result:
            user_rating = rating_result['rating']

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
    """Add comment with XSS protection"""
    content = request.form.get('content', '').strip()
    if not content:
        flash('Comment cannot be empty', 'warning')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))

    # Sanitize input to prevent XSS
    clean_content = sanitize_comment(content)

    conn = get_db_connection()
    conn.execute('''
        INSERT INTO comments (content, recipe_id, user_id)
        VALUES (?, ?, ?)
    ''', (clean_content, recipe_id, session['user_id']))
    conn.commit()
    conn.close()

    flash('Comment added', 'success')
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

@app.route('/rate/<int:recipe_id>', methods=['POST'])
@login_required
def rate_recipe(recipe_id):
    """Rate a recipe"""
    rating = request.form.get('rating', type=int)

    if not rating or rating < 1 or rating > 5:
        flash('Invalid rating', 'danger')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))

    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO ratings (rating, recipe_id, user_id)
            VALUES (?, ?, ?)
            ON CONFLICT(recipe_id, user_id) DO UPDATE SET rating = ?
        ''', (rating, recipe_id, session['user_id'], rating))
        conn.commit()
        flash(f'Rating of {rating} stars added', 'success')
    except Exception:
        flash('Error adding rating', 'danger')
    conn.close()

    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

@app.route('/favorite/<int:recipe_id>', methods=['POST'])
@login_required
def toggle_favorite(recipe_id):
    """Toggle recipe favorite"""
    conn = get_db_connection()

    existing = conn.execute(
        'SELECT id FROM favorites WHERE recipe_id = ? AND user_id = ?',
        (recipe_id, session['user_id'])
    ).fetchone()

    if existing:
        conn.execute('DELETE FROM favorites WHERE recipe_id = ? AND user_id = ?',
                    (recipe_id, session['user_id']))
        flash('Removed from favorites', 'info')
    else:
        conn.execute('INSERT INTO favorites (recipe_id, user_id) VALUES (?, ?)',
                    (recipe_id, session['user_id']))
        flash('Added to favorites', 'success')

    conn.commit()
    conn.close()
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

@app.route('/profile/<username>')
def profile(username):
    """User profile page"""
    conn = get_db_connection()

    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        flash('User not found', 'danger')
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

    # Get favorites
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
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        ingredients = request.form.get('ingredients', '').strip()
        instructions = request.form.get('instructions', '').strip()
        category = request.form.get('category', '').strip()
        difficulty = request.form.get('difficulty', '').strip()
        prep_time = request.form.get('prep_time', type=int)
        cook_time = request.form.get('cook_time', type=int)
        servings = request.form.get('servings', type=int)
        image_url = request.form.get('image_url', '').strip()

        if not title or not description or not ingredients or not instructions:
            flash('Please fill in all required fields', 'danger')
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

        flash('Recipe added successfully', 'success')
        return redirect(url_for('home'))

    return render_template('add_recipe.html')

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(429)
def ratelimit_error(e):
    """Rate limit exceeded"""
    flash('Too many requests. Please try again later.', 'danger')
    return redirect(url_for('home')), 429

@app.errorhandler(404)
def not_found(e):
    """Page not found"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Server error"""
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
