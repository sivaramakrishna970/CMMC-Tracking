import os
from datetime import datetime
from functools import wraps

from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cmmc_tracking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    company = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CMMCLevel(db.Model):
    __tablename__ = 'cmmc_level'
    id = db.Column(db.Integer, primary_key=True)
    level_number = db.Column(db.Integer, unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CMMCDomain(db.Model):
    __tablename__ = 'cmmc_domain'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CMMCRequirement(db.Model):
    __tablename__ = 'cmmc_requirement'
    id = db.Column(db.Integer, primary_key=True)
    requirement_id = db.Column(db.String(20), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    level_id = db.Column(db.Integer, db.ForeignKey('cmmc_level.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('cmmc_domain.id'), nullable=False)
    guidance = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    level = db.relationship('CMMCLevel', backref='requirements')
    domain = db.relationship('CMMCDomain', backref='requirements')

class ComplianceRecord(db.Model):
    __tablename__ = 'compliance_record'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requirement_id = db.Column(db.Integer, db.ForeignKey('cmmc_requirement.id'), nullable=False)
    status = db.Column(db.String(20), default='not_started')  # 'compliant', 'non_compliant', 'in_progress', 'not_started'
    artifact_path = db.Column(db.String(500))
    notes = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='compliance_records')
    requirement = db.relationship('CMMCRequirement', backref='compliance_records')

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        company = request.form['company']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            company=company
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    
    # Get compliance summary
    total_requirements = CMMCRequirement.query.count()
    user_records = ComplianceRecord.query.filter_by(user_id=user.id).all()
    
    compliant_count = sum(1 for record in user_records if record.status == 'compliant')
    in_progress_count = sum(1 for record in user_records if record.status == 'in_progress')
    non_compliant_count = sum(1 for record in user_records if record.status == 'non_compliant')
    not_started_count = total_requirements - len(user_records)
    
    # Progress by level
    levels = CMMCLevel.query.all()
    level_progress = {}
    for level in levels:
        level_requirements = CMMCRequirement.query.filter_by(level_id=level.id).all()
        level_compliant = 0
        for req in level_requirements:
            record = ComplianceRecord.query.filter_by(user_id=user.id, requirement_id=req.id).first()
            if record and record.status == 'compliant':
                level_compliant += 1
        
        level_progress[level.level_number] = {
            'total': len(level_requirements),
            'compliant': level_compliant,
            'percentage': (level_compliant / len(level_requirements)) * 100 if level_requirements else 0
        }
    
    # Progress by domain
    domains = CMMCDomain.query.all()
    domain_progress = {}
    for domain in domains:
        domain_requirements = CMMCRequirement.query.filter_by(domain_id=domain.id).all()
        domain_compliant = 0
        for req in domain_requirements:
            record = ComplianceRecord.query.filter_by(user_id=user.id, requirement_id=req.id).first()
            if record and record.status == 'compliant':
                domain_compliant += 1
        
        domain_progress[domain.code] = {
            'name': domain.name,
            'total': len(domain_requirements),
            'compliant': domain_compliant,
            'percentage': (domain_compliant / len(domain_requirements)) * 100 if domain_requirements else 0
        }
    
    summary = {
        'total': total_requirements,
        'compliant': compliant_count,
        'in_progress': in_progress_count,
        'non_compliant': non_compliant_count,
        'not_started': not_started_count,
        'overall_percentage': (compliant_count / total_requirements) * 100 if total_requirements > 0 else 0
    }
    
    return render_template('dashboard.html', user=user, summary=summary, 
                         level_progress=level_progress, domain_progress=domain_progress)

@app.route('/requirements')
@login_required
def requirements():
    level_filter = request.args.get('level')
    domain_filter = request.args.get('domain')
    
    query = CMMCRequirement.query
    if level_filter:
        query = query.filter_by(level_id=level_filter)
    if domain_filter:
        query = query.filter_by(domain_id=domain_filter)
    
    requirements = query.all()
    levels = CMMCLevel.query.all()
    domains = CMMCDomain.query.all()
    
    # Get user's compliance records
    user_records = {}
    for record in ComplianceRecord.query.filter_by(user_id=session['user_id']).all():
        user_records[record.requirement_id] = record
    
    return render_template('requirements.html', requirements=requirements, 
                         levels=levels, domains=domains, user_records=user_records)

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin/index.html')

@app.route('/admin/requirements')
@admin_required
def admin_requirements():
    requirements = CMMCRequirement.query.all()
    levels = CMMCLevel.query.all()
    domains = CMMCDomain.query.all()
    return render_template('admin/requirements.html', requirements=requirements, 
                         levels=levels, domains=domains)

@app.route('/admin/requirements/add', methods=['GET', 'POST'])
@admin_required
def admin_add_requirement():
    if request.method == 'POST':
        requirement = CMMCRequirement(
            requirement_id=request.form['requirement_id'],
            title=request.form['title'],
            description=request.form['description'],
            level_id=request.form['level_id'],
            domain_id=request.form['domain_id'],
            guidance=request.form['guidance']
        )
        db.session.add(requirement)
        db.session.commit()
        flash('Requirement added successfully!', 'success')
        return redirect(url_for('admin_requirements'))
    
    levels = CMMCLevel.query.all()
    domains = CMMCDomain.query.all()
    return render_template('admin/add_requirement.html', levels=levels, domains=domains)

@app.route('/admin/levels')
@admin_required
def admin_levels():
    levels = CMMCLevel.query.all()
    return render_template('admin/levels.html', levels=levels)

@app.route('/admin/levels/add', methods=['GET', 'POST'])
@admin_required
def admin_add_level():
    if request.method == 'POST':
        level = CMMCLevel(
            level_number=request.form['level_number'],
            name=request.form['name'],
            description=request.form['description']
        )
        db.session.add(level)
        db.session.commit()
        flash('Level added successfully!', 'success')
        return redirect(url_for('admin_levels'))
    
    return render_template('admin/add_level.html')

@app.route('/admin/domains')
@admin_required
def admin_domains():
    domains = CMMCDomain.query.all()
    return render_template('admin/domains.html', domains=domains)

@app.route('/admin/domains/add', methods=['GET', 'POST'])
@admin_required
def admin_add_domain():
    if request.method == 'POST':
        domain = CMMCDomain(
            code=request.form['code'],
            name=request.form['name'],
            description=request.form['description']
        )
        db.session.add(domain)
        db.session.commit()
        flash('Domain added successfully!', 'success')
        return redirect(url_for('admin_domains'))
    
    return render_template('admin/add_domain.html')

@app.route('/admin/reports')
@admin_required
def admin_reports():
    # Overall compliance statistics
    total_users = User.query.filter_by(role='user').count()
    total_requirements = CMMCRequirement.query.count()
    total_records = ComplianceRecord.query.count()
    
    # Compliance by level
    levels = CMMCLevel.query.all()
    level_stats = {}
    for level in levels:
        level_requirements = CMMCRequirement.query.filter_by(level_id=level.id).all()
        compliant_records = 0
        for req in level_requirements:
            compliant_records += ComplianceRecord.query.filter_by(
                requirement_id=req.id, status='compliant'
            ).count()
        
        level_stats[level.level_number] = {
            'name': level.name,
            'total_possible': len(level_requirements) * total_users,
            'compliant': compliant_records,
            'percentage': (compliant_records / (len(level_requirements) * total_users)) * 100 
                         if level_requirements and total_users > 0 else 0
        }
    
    # Recent activity
    recent_records = ComplianceRecord.query.order_by(
        ComplianceRecord.updated_at.desc()
    ).limit(10).all()
    
    return render_template('admin/reports.html', 
                         total_users=total_users,
                         total_requirements=total_requirements,
                         total_records=total_records,
                         level_stats=level_stats,
                         recent_records=recent_records)

@app.route('/compliance/<int:requirement_id>', methods=['GET', 'POST'])
@login_required
def compliance_record(requirement_id):
    requirement = CMMCRequirement.query.get_or_404(requirement_id)
    record = ComplianceRecord.query.filter_by(
        user_id=session['user_id'], 
        requirement_id=requirement_id
    ).first()
    
    if request.method == 'POST':
        status = request.form['status']
        notes = request.form['notes']
        
        if record:
            record.status = status
            record.notes = notes
            record.updated_at = datetime.utcnow()
        else:
            record = ComplianceRecord(
                user_id=session['user_id'],
                requirement_id=requirement_id,
                status=status,
                notes=notes
            )
            db.session.add(record)
        
        db.session.commit()
        flash('Compliance record updated successfully!', 'success')
        return redirect(url_for('requirements'))
    
    return render_template('compliance_record.html', requirement=requirement, record=record)

@app.route('/api/compliance-summary')
@login_required
def api_compliance_summary():
    user_id = session['user_id']
    
    # Get overall stats
    total_requirements = CMMCRequirement.query.count()
    user_records = ComplianceRecord.query.filter_by(user_id=user_id).all()
    
    status_counts = {
        'compliant': 0,
        'non_compliant': 0,
        'in_progress': 0,
        'not_started': total_requirements - len(user_records)
    }
    
    for record in user_records:
        if record.status in status_counts:
            status_counts[record.status] += 1
    
    return jsonify(status_counts)

def init_database():
    """Initialize the database with sample data"""
    db.create_all()
    
    # Create admin user if it doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            company='System Administrator'
        )
        db.session.add(admin)
    
    # Add CMMC Levels
    if not CMMCLevel.query.first():
        levels = [
            CMMCLevel(level_number=1, name="Basic Cyber Hygiene", 
                     description="Basic cybersecurity practices"),
            CMMCLevel(level_number=2, name="Intermediate Cyber Hygiene", 
                     description="Implementation of NIST SP 800-171 practices"),
            CMMCLevel(level_number=3, name="Good Cyber Hygiene", 
                     description="Advanced cybersecurity practices")
        ]
        for level in levels:
            db.session.add(level)
    
    # Add CMMC Domains
    if not CMMCDomain.query.first():
        domains = [
            CMMCDomain(code="AC", name="Access Control", 
                      description="Limit information system access to authorized users"),
            CMMCDomain(code="AU", name="Audit and Accountability", 
                      description="Create, protect, and retain system audit records"),
            CMMCDomain(code="AT", name="Awareness and Training", 
                      description="Ensure that personnel are trained in cybersecurity"),
            CMMCDomain(code="CM", name="Configuration Management", 
                      description="Establish and maintain baseline configurations"),
            CMMCDomain(code="IA", name="Identification and Authentication", 
                      description="Identify and authenticate users and devices"),
            CMMCDomain(code="IR", name="Incident Response", 
                      description="Establish operational incident response capability"),
            CMMCDomain(code="MA", name="Maintenance", 
                      description="Perform maintenance on systems and components"),
            CMMCDomain(code="MP", name="Media Protection", 
                      description="Protect and control information and media"),
            CMMCDomain(code="PS", name="Personnel Security", 
                      description="Ensure trustworthiness of personnel"),
            CMMCDomain(code="PE", name="Physical Protection", 
                      description="Limit physical access to systems and equipment"),
            CMMCDomain(code="RA", name="Risk Assessment", 
                      description="Assess and manage organizational risk"),
            CMMCDomain(code="CA", name="Security Assessment", 
                      description="Develop and implement security assessment plans"),
            CMMCDomain(code="SC", name="System and Communications Protection", 
                      description="Monitor and control communications"),
            CMMCDomain(code="SI", name="System and Information Integrity", 
                      description="Identify, report, and correct system flaws")
        ]
        for domain in domains:
            db.session.add(domain)
    
    # Add sample requirements
    if not CMMCRequirement.query.first():
        sample_requirements = [
            {
                "requirement_id": "AC.L1-3.1.1",
                "title": "Authorized Access Control",
                "description": "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).",
                "level": 1,
                "domain": "AC",
                "guidance": "Implement user accounts and access controls. Use strong passwords and multi-factor authentication where possible."
            },
            {
                "requirement_id": "AC.L1-3.1.2", 
                "title": "Transaction and Function Control",
                "description": "Limit information system access to the types of transactions and functions that authorized users are permitted to execute.",
                "level": 1,
                "domain": "AC",
                "guidance": "Implement role-based access control (RBAC) to ensure users can only access functions they need for their job."
            },
            {
                "requirement_id": "AU.L2-3.3.1",
                "title": "Audit Events",
                "description": "Create and retain information system audit records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized information system activity.",
                "level": 2,
                "domain": "AU",
                "guidance": "Configure logging on all systems and ensure logs are retained for at least 90 days. Monitor for suspicious activities."
            }
        ]
        
        for req_data in sample_requirements:
            level = CMMCLevel.query.filter_by(level_number=req_data['level']).first()
            domain = CMMCDomain.query.filter_by(code=req_data['domain']).first()
            
            requirement = CMMCRequirement(
                requirement_id=req_data['requirement_id'],
                title=req_data['title'],
                description=req_data['description'],
                level_id=level.id,
                domain_id=domain.id,
                guidance=req_data['guidance']
            )
            db.session.add(requirement)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_database()
    app.run(debug=True)
