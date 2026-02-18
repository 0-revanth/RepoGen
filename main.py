from flask import Flask, render_template, request, send_file, send_from_directory, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import pandas as pd
import os
import secrets
import string

from generate_pdf import generate_pdf_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production-12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    profile_picture = db.Column(db.String(200), nullable=True)  # Store filename
    organization_code = db.Column(db.String(50), nullable=True)  # Links user to admin's org
    is_admin = db.Column(db.Boolean, default=False)  # True if admin, False if regular user
    organization_name = db.Column(db.String(200), nullable=True)  # For admins only
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ReportLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    organization_code = db.Column(db.String(50), nullable=False)
    report_code = db.Column(db.String(50), unique=True, nullable=False)
    project_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to access user details
    user = db.relationship('User', backref=db.backref('reports', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper function to generate unique organization code
def generate_org_code(prefix="ORG"):
    """Generate unique 8-character organization code with custom prefix"""
    # Ensure prefix is 3 chars and uppercase
    prefix = prefix[:3].upper() if prefix else "ORG"
    if len(prefix) < 3:
        prefix = prefix.ljust(3, 'X')
        
    while True:
        # Generate 5 random chars to make total length 8 (3 prefix + 5 random)
        random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(5))
        code = f"{prefix}-{random_part}"
        
        # Check if code already exists
        if not User.query.filter_by(organization_code=code).first():
            return code

# Create database tables
with app.app_context():
    db.create_all()

REQUIRED_COLUMNS = {
    "Vulnerability", "Severity", "CVSS Score", "Status"
}

# ==================== AUTHENTICATION ROUTES ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Try to find user by email or phone
        user = User.query.filter((User.email == username) | (User.phone == username)).first()
        
        if user and user.check_password(password):
            # Check if user is admin trying to login via user login
            if user.is_admin:
                flash('Please use Admin Login for admin accounts', 'error')
                return redirect(url_for('admin_login'))
            
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid email/phone or password', 'error')
    
    return render_template("login.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('index'))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Try to find user by email or phone
        user = User.query.filter((User.email == username) | (User.phone == username)).first()
        
        if user and user.check_password(password):
            # Check if user is actually an admin
            if not user.is_admin:
                flash('Access denied. This account is not an admin account.', 'error')
                return redirect(url_for('login'))
            
            login_user(user)
            return redirect(url_for('admin'))
        else:
            flash('Invalid email/phone or password', 'error')
    
    return render_template("admin_login.html")

@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        gender = request.form.get("gender")
        password = request.form.get("password")
        organization_name = request.form.get("organization_name")
        org_prefix = request.form.get("org_prefix")
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template("admin_register.html")
        
        if User.query.filter_by(phone=phone).first():
            flash('Phone number already registered', 'error')
            return render_template("admin_register.html")
        
        # Generate unique organization code with custom prefix
        org_code = generate_org_code(org_prefix)
        
        # Create new admin user
        new_admin = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            gender=gender,
            organization_code=org_code,
            organization_name=organization_name,
            is_admin=True
        )
        new_admin.set_password(password)
        
        db.session.add(new_admin)
        db.session.commit()
        
        # Show success message with org code
        flash(f'Admin registration successful! Your Organization Code is: {org_code}', 'success')
        flash('Please share this code with your team members for registration.', 'info')
        return redirect(url_for('admin_login'))
    
    return render_template("admin_register.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        gender = request.form.get("gender")
        password = request.form.get("password")
        organization_code = request.form.get("organization_code")
        
        # Validate organization code
        admin = User.query.filter_by(organization_code=organization_code, is_admin=True).first()
        if not admin:
            flash('Invalid organization code. Please check with your administrator.', 'error')
            return render_template("register.html")
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template("register.html")
        
        if User.query.filter_by(phone=phone).first():
            flash('Phone number already registered', 'error')
            return render_template("register.html")
        
        # Create new user linked to organization
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            gender=gender,
            organization_code=organization_code,
            is_admin=False
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        # Update user details
        current_user.first_name = request.form.get("first_name")
        current_user.last_name = request.form.get("last_name")
        current_user.phone = request.form.get("phone")
        current_user.gender = request.form.get("gender")
        
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                # Delete old profile picture if exists
                if current_user.profile_picture:
                    old_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_picture)
                    if os.path.exists(old_pic_path):
                        os.remove(old_pic_path)
                
                # Save new profile picture
                filename = secure_filename(file.filename)
                # Add user ID to filename to make it unique
                filename = f"user_{current_user.id}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.profile_picture = filename
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template("edit_profile.html", user=current_user)

@app.route("/admin/reports")
@login_required
def admin_reports():
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect(url_for('index'))
    
    query = request.args.get('q', '').strip()
    
    base_query = ReportLog.query.join(User).filter(
        ReportLog.organization_code == current_user.organization_code
    )
    
    if query:
        search = f"%{query}%"
        base_query = base_query.filter(
            (ReportLog.report_code.like(search)) |
            (User.first_name.like(search)) |
            (User.last_name.like(search)) |
            (User.email.like(search))
        )
    
    logs = base_query.order_by(ReportLog.created_at.desc()).all()
    
    return render_template("admin_reports.html", logs=logs)

@app.route("/admin")
@login_required
def admin():
    # Check if user is an admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Filter users by admin's organization code (exclude admin themselves)
    users = User.query.filter_by(
        organization_code=current_user.organization_code,
        is_admin=False
    ).order_by(User.created_at.desc()).all()
    
    return render_template("admin.html", 
                         users=users, 
                         total_users=len(users),
                         org_code=current_user.organization_code,
                         org_name=current_user.organization_name)

# ==================== MAIN APP ROUTES ====================

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route('/assets/<path:path>')
def send_assets(path):
    return send_from_directory('assets', path)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    project_name = request.form.get(
        "project_name", "Security Assessment Report"
    )
    password = request.form.get("password")  # Get password
    excel_files = request.files.getlist("excel_files")

    vulnerabilities = []
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for file in excel_files:
        if file and file.filename.endswith((".xlsx", ".xls")):
            df = pd.read_excel(file)

            # if not REQUIRED_COLUMNS.issubset(df.columns):
            #     continue

            for _, row in df.iterrows():
                sev = str(row["Severity"]).upper()
                if sev in severity_count:
                    severity_count[sev] += 1

                vulnerabilities.append({
                    "vuln_id": str(row.get("Vulnerability ID", "N/A")),
                    "severity": sev,
                    "cvss_score": str(row.get("CVSS Score", "N/A")),
                    "cvss_id": str(row.get("CVSS ID", "N/A")),
                    "affected_systems": str(row.get("Affected Systems", "N/A")),
                    "query_param": str(row.get("Query Parameter", "N/A")),
                    "injection_point": str(row.get("Injection Point", "N/A")),
                    "status": str(row.get("Status", "OPEN")).upper(),
                    "category": str(row.get("Category", "N/A")),
                    "findings": str(row.get("Findings", "N/A")),
                    "impact": str(row.get("Impact", "N/A")),
                    "remediation": str(row.get("Remediation", "N/A")),
                    "affected_component": str(row.get("Affected Component", "N/A")),
                    "url": str(row.get("URL", "N/A")),
                    "reference": str(row.get("Reference Link", "N/A")),
                })

    if not vulnerabilities:
        vulnerabilities = [
            ["SQL Injection", "CRITICAL", "9.8", "OPEN"],
            ["XSS", "HIGH", "7.5", "OPEN"]
        ]
        severity_count["CRITICAL"] = 1
        severity_count["HIGH"] = 1

    print("DEBUG TYPE:", type(vulnerabilities[0]))
    print("DEBUG VALUE:", vulnerabilities[0])

    # 🔥 PDF generation happens HERE
    # Generate unique report code
    # Format: PREFIX-YYMMDD-XXXX
    org_prefix = current_user.organization_code.split('-')[0] if current_user.organization_code else "REP"
    timestamp_str = datetime.now().strftime("%y%m%d")
    random_suffix = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    report_code = f"{org_prefix}-{timestamp_str}-{random_suffix}"
    
    # Log the report generation
    new_log = ReportLog(
        user_id=current_user.id,
        organization_code=current_user.organization_code if current_user.organization_code else "UNKNOWN",
        report_code=report_code,
        project_name=project_name
    )
    db.session.add(new_log)
    db.session.commit()

    # Generate PDF with the report code as watermark
    pdf_buffer = generate_pdf_report(project_name, vulnerabilities, severity_count, password, report_code)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"{project_name}_report.pdf",
        mimetype="application/pdf"
    )

if __name__ == "__main__":
    app.run(debug=True)
