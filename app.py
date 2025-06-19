from flask import Flask, request, jsonify, send_file, render_template, url_for, redirect, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from openpyxl import Workbook
import qrcode
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    attendances = db.relationship('Attendance', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Attendance model
class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables
with app.app_context():
    db.create_all()
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),  # Change this in production!
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# Routes
@app.route('/')
def home():
    return render_template('title.html')

@app.route('/dashboard')
def dashboard():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_download'))  # Fix admin login redirect
            return redirect(url_for('qr_page'))
        
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/index')
def index():
    return render_template('index.html', qr_url=url_for('generate_qr', _external=True))

@app.route('/qr-page')
def qr_page():
    return render_template('qr_page.html')

@app.route('/generate-qr')
def generate_qr():
    # Get actual WiFi IP (192.168.29.186)
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to connect to anything, just gets local IP
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
        
    attendance_url = f"http://{ip}:5004/mark-attendance"
    print(f"Network QR code URL: {attendance_url}")
    img = qrcode.make(attendance_url)
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

@app.route('/mark-attendance', methods=['GET', 'POST'])
def mark_attendance():
    if request.method == 'POST':
        # Handle both form and JSON requests
        if request.is_json:
            data = request.get_json()
            name = data.get('name')
            email = data.get('email')
        else:
            name = request.form.get('name')
            email = request.form.get('email')
        
        # Check for duplicates
        if Attendance.query.filter_by(email=email).first():
            return jsonify({"error": "Already marked attendance"}), 400
            
        # Create record
        db.session.add(Attendance(
            name=name,
            email=email,
            user_id=None
        ))
        db.session.commit()
        return jsonify({"message": "Attendance marked successfully"})
        
    return render_template('mark_attendance.html')

@app.route('/export/attendance')
@login_required
def export_attendance():
    if not current_user.is_admin:
        return "Unauthorized", 403
    
    records = Attendance.query.all()
    wb = Workbook()
    ws = wb.active
    ws.append(['Name', 'Email', 'Time of Attendance', 'Marked By'])
    
    for record in records:
        user = User.query.get(record.user_id)
        ws.append([record.name, record.email, record.timestamp, user.username if user else 'Unknown'])
    
    filename = 'attendance.xlsx'
    wb.save(filename)
    
    response = send_file(
        filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True
    )
    
    os.remove(filename)
    return response

@app.route('/admin')
@login_required
def admin_download():
    if not current_user.is_admin:
        return "Unauthorized", 403
    
    # Create Excel file
    records = Attendance.query.all()
    wb = Workbook()
    ws = wb.active
    ws.append(['Name', 'Email', 'Time of Attendance', 'Marked By'])
    
    for record in records:
        user = User.query.get(record.user_id)
        ws.append([record.name, record.email, record.timestamp, user.username if user else 'Unknown'])
    
    # Save and send file
    filename = 'attendance.xlsx'
    wb.save(filename)
    return send_file(
        filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True
    )

if __name__ == '__main__':
    # Get network IP for debugging
    import socket
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        print(f"\n\nServer accessible at:\n- http://localhost:5004 (local)\n- http://{ip}:5004 (network)\n")
    except:
        ip = 'localhost'
    
    app.run(debug=True, 
            port=5004, 
            host='0.0.0.0',
            threaded=True)
