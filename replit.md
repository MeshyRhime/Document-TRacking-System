# Document Tracking System - Authentication Module

## Overview
A complete web-based user authentication system built with PHP, MySQL, HTML5, CSS3 (Bootstrap), and JavaScript. The system provides secure user registration with email verification and multi-factor login with OTP authentication.

## Features Implemented

### User Registration
- Multi-step signup process with email verification
- Required fields: First Name, Last Name, Address, ID Number, Department, Year (1-5), Email, Username, Password
- Password validation (8-12 characters with letters, numbers, and special characters)
- Email verification with 6-digit OTP before account creation
- Duplicate prevention for username, email, and ID number

### User Authentication  
- Multi-step login process
- Step 1: Username/Password validation
- Step 2: Two-factor authentication selection (Email OTP)
- Step 3: 6-digit OTP verification via email
- Session management and security

### Email Integration
- Gmail SMTP integration for sending OTP codes
- Professional email templates with system branding
- HTML-formatted emails with responsive design
- OTP expiration (10 minutes for login, 15 minutes for signup verification)

## Technical Architecture

### Frontend
- **HTML5**: Semantic structure with Bootstrap 5.3.2 framework
- **CSS3**: Custom color scheme (#ff9966, #ffb380, #e68553) with gradient backgrounds
- **JavaScript**: AJAX-based form handling with comprehensive state management
- **Icons**: Bootstrap Icons for enhanced UX

### Backend  
- **PHP 8.2**: Object-oriented architecture with service classes
- **PostgreSQL**: Secure user data storage with proper indexing
- **Email Service**: Gmail SMTP for OTP delivery
- **Security**: Password hashing, OTP expiration, SQL injection prevention

### Database Schema
```sql
-- Users table
users (id, first_name, last_name, address, id_number, department, year, email, username, password, email_verified, created_at, updated_at)

-- OTP codes table  
otp_codes (id, email, otp_code, created_at, expires_at, used)
```

## Security Features
- BCrypt password hashing
- SQL prepared statements to prevent injection
- OTP code expiration and single-use enforcement
- Input validation on both frontend and backend
- CORS headers for secure API access

## User Experience
- Responsive design that works on all devices
- Real-time form validation with visual feedback
- Password visibility toggles with eye icons
- Loading states and progress indicators
- Professional alert system for user notifications
- Smooth view transitions and animations

## Email Configuration
- SMTP Host: smtp.gmail.com
- Port: 587 (TLS)  
- From: systemdtrack@gmail.com
- Authentication: App-specific password

## Project Structure
```
/
├── index.html          # Main application interface
├── styles.css          # Custom styling with Bootstrap
├── script.js           # Frontend JavaScript logic
├── auth.php           # Backend authentication API
├── database.sql       # Database schema
└── replit.md         # Project documentation
```

## Recent Changes (September 7, 2025)
- Initial implementation of complete authentication system
- Database setup with PostgreSQL integration
- Email OTP functionality implementation
- Bootstrap 5 styling with custom color scheme
- Multi-step login and registration flows
- Password strength validation
- Security hardening and error handling

## Development Status
✅ User registration with email verification
✅ Multi-factor authentication with OTP
✅ Database integration with PostgreSQL  
✅ Email service with Gmail SMTP
✅ Responsive UI with Bootstrap styling
✅ Security features and validation
✅ Error handling and user feedback

The system is production-ready for user authentication needs.