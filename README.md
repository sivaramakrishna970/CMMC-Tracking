# CMMC Tracking System

A comprehensive web-based system for tracking and managing Cybersecurity Maturity Model Certification (CMMC) compliance for Defense Industrial Base contractors.

## Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone or download the project**
   ```bash
   cd "CMMC Tracking"
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the application**
   - Open your web browser and go to: `http://localhost:5000`
   - The application will automatically initialize with sample data

### Demo Login Credentials

**Administrator:**
- Username: `admin`
- Password: `admin123`

**Regular User:**
- Register a new account or use any existing user credentials

## Features

### Admin Panel
- **Requirements Management**: Add, edit, and organize CMMC requirements across all levels and domains
- **Level Configuration**: Manage CMMC maturity levels (Basic, Intermediate, Good Cyber Hygiene)
- **Domain Management**: Configure security domains (AC, AU, AT, CM, IA, IR, MA, MP, PS, PE, RA, CA, SC, SI)
- **System Reports**: Comprehensive analytics and compliance statistics
- **User Management**: View system-wide compliance progress

### Summation & Dashboard
- **Progress Tracking**: Real-time compliance progress visualization
- **Level-wise Analysis**: Progress breakdown by CMMC levels
- **Domain Analysis**: Compliance status across security domains
- **Interactive Charts**: Visual representation using Chart.js
- **Quick Actions**: Direct access to requirements and compliance updates

### User Features
- **Compliance Tracking**: Update compliance status for individual requirements
- **Evidence Management**: Document implementation notes and approaches
- **Progress Visualization**: Personal compliance dashboard
- **Requirement Browsing**: Filter and view requirements by level and domain
- **Implementation Guidance**: Access detailed guidance for each requirement

## System Architecture

### Database Models
- **Users**: Authentication and role management
- **CMMC Levels**: Maturity level definitions
- **CMMC Domains**: Security domain organization
- **CMMC Requirements**: Individual compliance requirements
- **Compliance Records**: User compliance tracking and evidence

### Technology Stack
- **Backend**: Flask (Python web framework)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML5, Tailwind CSS, Chart.js
- **Authentication**: Flask session-based authentication
- **UI Icons**: Font Awesome

## Project Structure

```
CMMC Tracking/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # Project documentation
├── templates/            # HTML templates
│   ├── base.html         # Base template with navigation
│   ├── index.html        # Landing page
│   ├── login.html        # User authentication
│   ├── register.html     # User registration
│   ├── dashboard.html    # Main dashboard with summation
│   ├── requirements.html # Requirements browsing
│   ├── compliance_record.html # Individual compliance updates
│   └── admin/           # Admin panel templates
│       ├── index.html    # Admin dashboard
│       ├── requirements.html # Manage requirements
│       ├── add_requirement.html # Add new requirement
│       ├── levels.html   # Manage levels
│       ├── add_level.html # Add new level
│       ├── domains.html  # Manage domains
│       ├── add_domain.html # Add new domain
│       └── reports.html  # System reports
└── static/              # Static assets (CSS, JS, images)
```

## Key Functional Requirements (Implemented)

### Admin Panel
- **Requirements Management**: Full CRUD operations for CMMC requirements
- **Level Management**: Configure and manage CMMC maturity levels
- **Domain Management**: Organize security domains and classifications
- **System Reports**: Analytics dashboard with compliance statistics
- **User Role Management**: Admin vs. user access control

### Summation & Progress Tracking
- **Compliance Dashboard**: Real-time progress visualization
- **Level Progress**: Track compliance across CMMC levels
- **Domain Progress**: Monitor compliance by security domains
- **Interactive Charts**: Visual progress representation
- **Summary Statistics**: Overall compliance metrics

### User Compliance Management
- **Status Tracking**: Mark requirements as compliant/non-compliant/in-progress
- **Evidence Documentation**: Add notes and implementation details
- **Requirement Filtering**: Browse by level and domain
- **Implementation Guidance**: Built-in best practices and recommendations

## Technical Implementation

### Database Initialization
The system automatically initializes with:
- **Sample CMMC Requirements**: Pre-loaded with key requirements from levels 1-3
- **Standard Domains**: All 14 CMMC security domains
- **Admin Account**: Default administrator for system management

### Security Features
- **Role-based Access Control**: Admin vs. user permissions
- **Session Management**: Secure user authentication
- **Password Hashing**: Werkzeug security for password protection
- **Input Validation**: Form validation and sanitization

### Responsive Design
- **Mobile-first Approach**: Works on all device sizes
- **Modern UI**: Clean, professional interface using Tailwind CSS
- **Accessibility**: Keyboard navigation and screen reader support

## Sample Data

The system comes pre-loaded with:
- **3 CMMC Levels**: Basic, Intermediate, and Good Cyber Hygiene
- **14 Security Domains**: Complete CMMC domain structure
- **Sample Requirements**: Representative requirements from each level
- **Admin User**: Ready-to-use administrator account

## Future Enhancements

### Planned Features
- **File Upload**: Artifact and evidence file management
- **Report Generation**: PDF/Excel export capabilities
- **Advanced Analytics**: Trend analysis and compliance forecasting
- **API Integration**: RESTful API for external integrations
- **Audit Trail**: Comprehensive change tracking
- **Multi-tenant Support**: Organization-based data isolation

### Scalability Considerations
- **Database Migration**: Easy upgrade to PostgreSQL/MySQL for production
- **Cloud Deployment**: Ready for AWS/Azure/GCP deployment
- **Load Balancing**: Stateless design for horizontal scaling
- **Caching**: Redis integration for improved performance

## Project Success Criteria (Met)

- **System handles full artifact lifecycle** (add, edit, delete compliance records)
- **Compliance progress accurately calculated** (real-time progress tracking)
- **System generates basic reports and guidance** (admin reports and implementation guidance)
- **User-friendly interface** (modern, responsive design with Tailwind CSS)
---
