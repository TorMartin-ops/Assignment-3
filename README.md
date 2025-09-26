# XSS Vulnerability Demonstration - Recipe Sharing Platform

## Overview
This web application demonstrates Cross-Site Scripting (XSS) vulnerabilities and their mitigation techniques. Built with Flask and SQLite, it intentionally contains security vulnerabilities for educational purposes.

## Features
- Recipe sharing platform with user-generated content
- Intentional XSS vulnerability in comment system
- Educational demonstration of web security concepts
- Clean, professional UI with Bootstrap styling

## Prerequisites
- Python 3.7 or higher
- Git

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/Assignment-2---Cross-Site-Scripting.git
cd Assignment-2---Cross-Site-Scripting
```

### 2. Create Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize Database
```bash
python database.py
```

### 5. Run the Application
```bash
python app.py
```

### 6. Access the Application
Open your web browser and navigate to: `http://localhost:5000`

## Testing XSS Vulnerability

1. Navigate to any recipe page
2. Scroll to the comments section
3. Try these XSS payloads in the comment form:
   - `<script>alert('XSS Attack!')</script>`
   - `<img src=x onerror=alert('Image XSS')>`
   - `<svg onload=alert('SVG XSS')>`

**Warning**: The application intentionally contains security vulnerabilities for educational purposes. Do not deploy this to production.

## Project Structure
```
Assignment-2---Cross-Site-Scripting/
├── app.py              # Main Flask application
├── database.py         # Database setup and initialization
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── .gitignore         # Git ignore rules
├── templates/         # HTML templates
│   ├── base.html
│   ├── home.html
│   └── recipe_detail.html
└── static/           # CSS, JS, images (if any)
```

## Educational Disclaimer
This application is for educational purposes only. The vulnerabilities demonstrated should never be implemented in production applications. Always follow security best practices when developing real-world web applications.

## License
This project is for educational use only.