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

@app.route('/admin/requirements/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_requirement(id):
    requirement = CMMCRequirement.query.get_or_404(id)
    
    if request.method == 'POST':
        requirement.requirement_id = request.form['requirement_id']
        requirement.title = request.form['title']
        requirement.description = request.form['description']
        requirement.level_id = request.form['level_id']
        requirement.domain_id = request.form['domain_id']
        requirement.guidance = request.form['guidance']
        
        db.session.commit()
        flash('Requirement updated successfully!', 'success')
        return redirect(url_for('admin_requirements'))
    
    levels = CMMCLevel.query.all()
    domains = CMMCDomain.query.all()
    return render_template('admin/edit_requirement.html', requirement=requirement, levels=levels, domains=domains)

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

@app.route('/admin/levels/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_level(id):
    level = CMMCLevel.query.get_or_404(id)
    
    if request.method == 'POST':
        level.level_number = request.form['level_number']
        level.name = request.form['name']
        level.description = request.form['description']
        
        db.session.commit()
        flash('Level updated successfully!', 'success')
        return redirect(url_for('admin_levels'))
    
    return render_template('admin/edit_level.html', level=level)

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

@app.route('/admin/domains/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_domain(id):
    domain = CMMCDomain.query.get_or_404(id)
    
    if request.method == 'POST':
        domain.code = request.form['code']
        domain.name = request.form['name']
        domain.description = request.form['description']
        
        db.session.commit()
        flash('Domain updated successfully!', 'success')
        return redirect(url_for('admin_domains'))
    
    return render_template('admin/edit_domain.html', domain=domain)

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
    """Initialize the database with CMMC Level 1 data as per the guide."""
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

    # Add CMMC Levels if they don't exist
    if not CMMCLevel.query.first():
        levels = [
            CMMCLevel(level_number=1, name="Basic Cyber Hygiene",
                      description="Focuses on the protection of Federal Contract Information (FCI) and encompasses the basic safeguarding requirements specified in FAR Clause 52.204-21."),
            CMMCLevel(level_number=2, name="Intermediate Cyber Hygiene",
                      description="Implementation of NIST SP 800-171 practices"),
            CMMCLevel(level_number=3, name="Good Cyber Hygiene",
                      description="Advanced cybersecurity practices")
        ]
        db.session.add_all(levels)

    # Add CMMC Domains if they don't exist
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
        db.session.add_all(domains)

    # Commit levels and domains so they can be queried for requirements
    db.session.commit()

    # Add CMMC Level 1 Requirements
    if not CMMCRequirement.query.filter_by(level_id=CMMCLevel.query.filter_by(level_number=1).first().id).first():
        level_1_requirements = [
            {
                "requirement_id": "AC.L1-3.1.1", "title": "Authorized Access Control", "domain": "AC",
                "description": "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).",
                "guidance": "Maintain a list of authorized users, processes, and devices. Ensure the system is configured to grant access only to those on the approved list."
            },
            {
                "requirement_id": "AC.L1-3.1.2", "title": "Transaction & Function Control", "domain": "AC",
                "description": "Limit information system access to the types of transactions and functions that authorized users are permitted to execute.",
                "guidance": "Use role-based access control (RBAC) to ensure users can only perform functions necessary for their job roles (e.g., create, read, update, delete)."
            },
            {
                "requirement_id": "AC.L1-3.1.20", "title": "External Connections", "domain": "AC",
                "description": "Verify and control/limit connections to and use of external information systems.",
                "guidance": "Use firewalls and connection policies to manage connections between your network and external ones. Control access from personally owned devices."
            },
            {
                "requirement_id": "AC.L1-3.1.22", "title": "Control Public Information", "domain": "AC",
                "description": "Control information posted or processed on publicly accessible information systems.",
                "guidance": "Establish a review process to prevent Federal Contract Information (FCI) from being posted on public systems like company websites or forums."
            },
            {
                "requirement_id": "IA.L1-3.5.1", "title": "Identification", "domain": "IA",
                "description": "Identify information system users, processes acting on behalf of users, or devices.",
                "guidance": "Assign unique identifiers (e.g., usernames) to all users, processes, and devices that require access to company systems."
            },
            {
                "requirement_id": "IA.L1-3.5.2", "title": "Authentication", "domain": "IA",
                "description": "Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems.",
                "guidance": "Verify identity before granting access, typically with a username and strong password. Always change default passwords on new devices and systems."
            },
            {
                "requirement_id": "MP.L1-3.8.3", "title": "Media Disposal", "domain": "MP",
                "description": "Sanitize or destroy information system media containing Federal Contract Information before disposal or release for reuse.",
                "guidance": "For any media containing FCI (e.g., paper, USB drives, hard drives), either physically destroy it or use a secure sanitization process to erase the data before disposal or reuse."
            },
            {
                "requirement_id": "PE.L1-3.10.1", "title": "Limit Physical Access", "domain": "PE",
                "description": "Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals.",
                "guidance": "Use locks, card readers, or other physical controls to restrict access to offices, server rooms, and equipment. Maintain a list of personnel with authorized physical access."
            },
            {
                "requirement_id": "PE.L1-3.10.3", "title": "Escort Visitors", "domain": "PE",
                "description": "Escort visitors and monitor visitor activity.",
                "guidance": "Ensure all visitors are escorted by an employee at all times within the facility and wear visitor identification."
            },
            {
                "requirement_id": "PE.L1-3.10.4", "title": "Physical Access Logs", "domain": "PE",
                "description": "Maintain audit logs of physical access.",
                "guidance": "Use a sign-in sheet or electronic system to log all individuals entering and leaving the facility. Retain these logs for a defined period."
            },
            {
                "requirement_id": "PE.L1-3.10.5", "title": "Manage Physical Access", "domain": "PE",
                "description": "Control and manage physical access devices.",
                "guidance": "Keep an inventory of all physical access devices like keys and key cards. Know who has them, and revoke access when personnel leave or change roles."
            },
            {
                "requirement_id": "SC.L1-3.13.1", "title": "Boundary Protection", "domain": "SC",
                "description": "Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems) at the external boundaries and key internal boundaries of the information systems.",
                "guidance": "Use firewalls to protect the boundary between your internal network and the internet, blocking unwanted traffic and malicious websites."
            },
            {
                "requirement_id": "SC.L1-3.13.5", "title": "Public-Access System Separation", "domain": "SC",
                "description": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
                "guidance": "Isolate publicly accessible systems (like a public website) from your internal network using a demilitarized zone (DMZ) or separate VLAN."
            },
            {
                "requirement_id": "SI.L1-3.14.1", "title": "Flaw Remediation", "domain": "SI",
                "description": "Identify, report, and correct information and information system flaws in a timely manner.",
                "guidance": "Implement a patch management process to fix software and firmware flaws within a defined timeframe based on vendor notifications."
            },
            {
                "requirement_id": "SI.L1-3.14.2", "title": "Malicious Code Protection", "domain": "SI",
                "description": "Provide protection from malicious code at appropriate locations within organizational information systems.",
                "guidance": "Use anti-virus and anti-malware software on workstations, servers, and firewalls to protect against malicious code like viruses and ransomware."
            },
            {
                "requirement_id": "SI.L1-3.14.4", "title": "Update Malicious Code Protection", "domain": "SI",
                "description": "Update malicious code protection mechanisms when new releases are available.",
                "guidance": "Configure anti-malware software to update its definition files automatically and frequently (e.g., daily) to protect against the latest threats."
            },
            {
                "requirement_id": "SI.L1-3.14.5", "title": "System & File Scanning", "domain": "SI",
                "description": "Perform periodic scans of the information system and real-time scans of files from external sources as files are downloaded, opened, or executed.",
                "guidance": "Configure anti-malware software to perform periodic full-system scans and real-time scans of files from external sources like email attachments and USB drives."
            }
        ]

        level1 = CMMCLevel.query.filter_by(level_number=1).first()

        for req_data in level_1_requirements:
            domain = CMMCDomain.query.filter_by(code=req_data['domain']).first()
            
            if domain:
                requirement = CMMCRequirement(
                    requirement_id=req_data['requirement_id'],
                    title=req_data['title'],
                    description=req_data['description'],
                    level_id=level1.id,
                    domain_id=domain.id,
                    guidance=req_data['guidance']
                )
                db.session.add(requirement)

    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_database()
    app.run(debug=True)
