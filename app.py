from flask import Flask, render_template

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Needed for sessions

@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)