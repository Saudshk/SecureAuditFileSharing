# Secure File Sharing System

## 🔒 Overview

The Secure File Sharing System is a cybersecurity-focused web application developed using Flask that enables users to securely upload, share, manage, and access files within an organization. The system is designed to provide a secure environment for exchanging sensitive information while implementing industry-standard security practices.

This project was developed as part of a cybersecurity and secure software development initiative, demonstrating the practical implementation of authentication, authorization, secure file handling, role-based access control, and data protection mechanisms.

The platform allows authorized users from different departments to exchange files securely, manage shared resources, and maintain accountability through activity logging and access controls.

---

## 🎯 Project Objectives

* Develop a secure platform for file sharing and management.
* Implement cybersecurity best practices in web application development.
* Protect sensitive organizational data from unauthorized access.
* Demonstrate secure authentication and authorization mechanisms.
* Provide a user-friendly interface while maintaining strong security controls.

---

## ✨ Features

### User Management

* User registration and login
* Secure authentication system
* Role-based access control
* Department-specific access permissions
* Session management

### File Sharing

* Secure file uploads
* Multiple file upload support
* File download functionality
* Department-based file sharing
* Public and private file sharing options
* Password-protected file transfers

### Security Features

* Secure password hashing
* File type validation
* Upload restrictions
* Input sanitization
* Access control mechanisms
* Session protection
* Protection against unauthorized file access
* Secure file storage practices
* Audit logging and monitoring

### User Interface

* Responsive web design
* Easy-to-use dashboard
* Department-specific views
* File management interface
* Modern and intuitive navigation

---

## 🏗️ System Architecture

The system follows a client-server architecture:

### Frontend

* HTML5
* CSS3
* Bootstrap
* JavaScript
* Jinja2 Templates

### Backend

* Python
* Flask Framework

### Database

* SQLite / MySQL

### Security Components

* Authentication System
* Authorization Layer
* File Validation Module
* Secure Storage Mechanism
* Activity Logging System

---

## 🛠️ Technologies Used

| Technology   | Purpose                     |
| ------------ | --------------------------- |
| Python       | Backend Development         |
| Flask        | Web Framework               |
| HTML5        | Structure                   |
| CSS3         | Styling                     |
| Bootstrap    | Responsive Design           |
| JavaScript   | Frontend Interactivity      |
| SQLite/MySQL | Database Management         |
| Jinja2       | Template Rendering          |
| Werkzeug     | Password Hashing & Security |

---

## 🔐 Security Implementation

The Secure File Sharing System incorporates multiple security controls to ensure the confidentiality, integrity, and availability of data.

### Authentication

* Secure login system
* Password hashing
* Session management

### Authorization

* Role-based access control
* Department-level permissions
* Restricted file access

### File Security

* File type validation
* Upload restrictions
* Secure file storage
* Controlled download access

### Input Validation

* Form validation
* Input sanitization
* Protection against malicious input

### Monitoring

* Activity logging
* User action tracking
* File access records

---

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/secure-file-sharing-system.git
cd secure-file-sharing-system
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

Windows:

```bash
venv\Scripts\activate
```

Linux/Mac:

```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the Application

```bash
python app.py
```

### 6. Open in Browser

```text
http://127.0.0.1:5000
```

---

## 📖 Usage

1. Register or log in to the system.
2. Access your department dashboard.
3. Upload one or multiple files securely.
4. Share files with authorized users.
5. Download files based on access permissions.
6. Monitor activities through logs and tracking features.

---

## 🧪 Testing

The system should be tested for:

* User authentication
* Access control enforcement
* File upload validation
* File download permissions
* Multiple file uploads
* Password-protected file sharing
* Security vulnerabilities
* User session handling

---



---

## 🔮 Future Enhancements

* End-to-end file encryption
* Multi-factor authentication (MFA)
* Email notifications
* File expiration dates
* Cloud storage integration
* Advanced audit reporting
* Secure file versioning
* Real-time sharing notifications
* API integration support

---

## 🎓 Educational Purpose

This project was developed as part of a cybersecurity-focused academic initiative to demonstrate secure software development principles, secure file management practices, and the implementation of security controls in modern web applications.

---

## 📜 License

This project is intended for educational and research purposes. Feel free to modify and extend it according to your requirements.

---

## 👨‍💻 Author

**Saud Shaikh**

Cybersecurity Student
University of West London (RAK Campus)

Focused on Cybersecurity, Penetration Testing, Network Security, Secure Software Development, and Digital Forensics.
