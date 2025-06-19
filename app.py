from flask import Flask, render_template, redirect, request, url_for, flash, current_app, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid

db = SQLAlchemy()
login_manager = LoginManager()

# Define models directly in the main file to avoid import issues
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100))
    contact = db.Column(db.String(20))
    course = db.Column(db.String(100))
    institution = db.Column(db.String(100))
    graduation_status = db.Column(db.String(50))
    skills = db.Column(db.Text)
    experience = db.Column(db.Text)
    projects = db.Column(db.Text)
    certifications = db.Column(db.Text)
    awards = db.Column(db.Text)

class CV(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
    
    # Fix the database path - use relative path or ensure the directory exists
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cv_drop.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Fix upload folder path
    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.route("/")
    def index():
        return render_template("index.html")

    # AUTH ROUTES
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        print(f"Registration route called with method: {request.method}")
        
        if request.method == 'POST':
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            # role = request.form.get('role', '')  # Remove this line
            
            print(f"Registration attempt: email={email}")
            
            # Validation
            if not email or not password:  # Remove 'or not role'
                print("Validation failed: missing fields")
                flash('All fields are required.', 'danger')
                return render_template('register.html')
            
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                print("User already exists")
                flash('Email already registered. Please log in or use a different email.', 'danger')
                return render_template('register.html')
            
            try:
                user = User(email=email, role='student')  # Set role to 'student'
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                print("User created successfully")
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                print(f"Registration error: {e}")
                db.session.rollback()
                flash('Registration failed. Please try again.', 'danger')
                
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            
            if not email or not password:
                flash('Email and password are required.', 'danger')
                return render_template('login.html')
            
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):
                login_user(user)
                flash(f'Welcome back!', 'success')
                
                # Redirect based on role
                if user.role == 'student':
                    return redirect(url_for('student_dashboard'))
                elif user.role == 'employer':
                    return redirect(url_for('employer_dashboard'))
                else:
                    flash('Invalid user role.', 'danger')
                    logout_user()
                    return render_template('login.html')
            else:
                flash('Invalid email or password.', 'danger')
                
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))

    # STUDENT ROUTES
    @app.route('/student/dashboard')
    @login_required
    def student_dashboard():
        if current_user.role != 'student':
            flash('Access denied. Students only.', 'danger')
            return redirect(url_for('login'))
        
        profile = Profile.query.filter_by(user_id=current_user.id).first()
        cvs = CV.query.filter_by(user_id=current_user.id).all()
        
        return render_template('student/dashboard.html', profile=profile, cvs=cvs)

    @app.route('/student/profile', methods=['GET', 'POST'])
    @login_required
    def student_profile():
        if current_user.role != 'student':
            flash('Access denied. Students only.', 'danger')
            return redirect(url_for('login'))
            
        profile = Profile.query.filter_by(user_id=current_user.id).first()
        
        if request.method == 'POST':
            try:
                if not profile:
                    profile = Profile(user_id=current_user.id)
                    db.session.add(profile)
                
                # Update profile fields
                profile.name = request.form.get('name', '').strip()
                profile.contact = request.form.get('contact', '').strip()
                profile.course = request.form.get('course', '').strip()
                profile.institution = request.form.get('institution', '').strip()
                profile.graduation_status = request.form.get('graduation_status', '')
                profile.skills = request.form.get('skills', '').strip()
                profile.experience = request.form.get('experience', '').strip()
                profile.projects = request.form.get('projects', '').strip()
                profile.certifications = request.form.get('certifications', '').strip()
                profile.awards = request.form.get('awards', '').strip()
                
                db.session.commit()
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('student_profile'))
                
            except Exception as e:
                db.session.rollback()
                flash('Error saving profile. Please try again.', 'danger')
                
        return render_template('student/profile.html', profile=profile)

    @app.route('/student/upload_cv', methods=['GET', 'POST'])
    @login_required
    def student_upload_cv():
        if current_user.role != 'student':
            flash('Access denied. Students only.', 'danger')
            return redirect(url_for('login'))

        if request.method == 'POST':
            try:
                # Prevent multiple uploads: check if student already has a CV
                existing_cv = CV.query.filter_by(user_id=current_user.id).first()
                if existing_cv:
                    flash('You have already uploaded a CV. Please delete your existing CV before uploading a new one.', 'warning')
                    return redirect(url_for('student_dashboard'))

                if 'cv' not in request.files:
                    flash('No file selected.', 'danger')
                    return redirect(request.url)

                file = request.files['cv']
                if file.filename == '':
                    flash('No file selected.', 'danger')
                    return redirect(request.url)

                # Validate file type
                allowed_extensions = {'pdf', 'doc', 'docx'}
                if not ('.' in file.filename and 
                        file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
                    flash('Invalid file type. Please upload PDF, DOC, or DOCX files only.', 'danger')
                    return redirect(request.url)

                # Save file
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                upload_folder = current_app.config['UPLOAD_FOLDER']

                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)

                filepath = os.path.join(upload_folder, unique_filename)
                file.save(filepath)

                # Save to database
                cv = CV(
                    user_id=current_user.id, 
                    filename=unique_filename, 
                    original_filename=filename
                )
                db.session.add(cv)
                db.session.commit()

                flash('CV uploaded successfully!', 'success')
                return redirect(url_for('student_dashboard'))

            except Exception as e:
                db.session.rollback()
                flash('Error uploading CV. Please try again.', 'danger')

        return render_template('student/upload_cv.html')

    @app.route('/student/download_cv/<int:cv_id>')
    @login_required
    def student_download_cv(cv_id):
        if current_user.role != 'student':
            flash('Access denied. Students only.', 'danger')
            return redirect(url_for('login'))
        cv = CV.query.get_or_404(cv_id)
        if cv.user_id != current_user.id:
            flash('You do not have permission to access this file.', 'danger')
            return redirect(url_for('student_dashboard'))
        upload_folder = current_app.config['UPLOAD_FOLDER']
        filepath = os.path.join(upload_folder, cv.filename)
        if not os.path.exists(filepath):
            flash('CV file not found.', 'danger')
            return redirect(url_for('student_dashboard'))
        try:
            return send_file(filepath, as_attachment=True, download_name=cv.original_filename)
        except Exception as e:
            flash('Error sending file.', 'danger')
            return redirect(url_for('student_dashboard'))

    @app.route('/student/delete_cv/<int:cv_id>', methods=['POST'])
    @login_required
    def student_delete_cv(cv_id):
        if current_user.role != 'student':
            flash('Access denied. Students only.', 'danger')
            return redirect(url_for('login'))
        cv = CV.query.get_or_404(cv_id)
        if cv.user_id != current_user.id:
            flash('You do not have permission to delete this file.', 'danger')
            return redirect(url_for('student_dashboard'))
        upload_folder = current_app.config['UPLOAD_FOLDER']
        filepath = os.path.join(upload_folder, cv.filename)
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
            db.session.delete(cv)
            db.session.commit()
            flash('CV deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error deleting CV. Please try again.', 'danger')
        return redirect(url_for('student_dashboard'))

    # ENHANCED EMPLOYER ROUTES
    @app.route('/employer/dashboard')
    @login_required
    def employer_dashboard():
        if current_user.role != 'employer':
            flash('Access denied. Employers only.', 'danger')
            return redirect(url_for('login'))
        # Handle case where there are no student profiles
        students = Profile.query.all() or []
        return render_template('employer/dashboard.html', students=students)

    @app.route('/employer/profile/<int:user_id>')
    @login_required
    def employer_view_profile(user_id):
        if current_user.role != 'employer':
            flash('Access denied. Employers only.', 'danger')
            return redirect(url_for('login'))
        profile = Profile.query.filter_by(user_id=user_id).first()
        cvs = CV.query.filter_by(user_id=user_id).all() if profile else []
        if not profile:
            flash('Profile not found.', 'danger')
            return redirect(url_for('employer_dashboard'))
        return render_template('employer/view_profile.html', profile=profile, cvs=cvs)

    @app.route('/employer/download_cv/<int:cv_id>')
    @login_required
    def employer_download_cv(cv_id):
        if current_user.role != 'employer':
            flash('Access denied. Employers only.', 'danger')
            return redirect(url_for('login'))
        cv = CV.query.get_or_404(cv_id)
        upload_folder = current_app.config['UPLOAD_FOLDER']
        filepath = os.path.join(upload_folder, cv.filename)
        if not os.path.exists(filepath):
            flash('CV file not found.', 'danger')
            return redirect(url_for('employer_dashboard'))
        try:
            return send_file(filepath, as_attachment=True, download_name=cv.original_filename)
        except Exception as e:
            flash('Error sending file.', 'danger')
            return redirect(url_for('employer_dashboard'))
        
    @app.route('/employer/view_cv/<int:cv_id>')
    @login_required
    def employer_view_cv(cv_id):
        if current_user.role != 'employer':
            flash('Access denied. Employers only.', 'danger')
            return redirect(url_for('login'))
        
        cv = CV.query.get_or_404(cv_id)
        upload_folder = current_app.config['UPLOAD_FOLDER']
        filepath = os.path.join(upload_folder, cv.filename)
        
        if not os.path.exists(filepath):
            flash('CV file not found.', 'danger')
            return redirect(url_for('employer_dashboard'))
        
        try:
            # For viewing in browser instead of downloading
            return send_file(filepath, as_attachment=False)
        except Exception as e:
            flash('Error displaying file.', 'danger')
            return redirect(url_for('employer_dashboard'))

    @app.route('/employer/delete_student/<int:user_id>', methods=['POST'])
    @login_required
    def employer_delete_student(user_id):
        if current_user.role != 'employer':
            flash('Access denied. Employers only.', 'danger')
            return redirect(url_for('login'))
        try:
            user = User.query.get(user_id)
            if not user:
                flash('User not found.', 'danger')
                return redirect(url_for('employer_dashboard'))
            profile = Profile.query.filter_by(user_id=user_id).first()
            cvs = CV.query.filter_by(user_id=user_id).all()
            upload_folder = current_app.config['UPLOAD_FOLDER']
            for cv in cvs:
                filepath = os.path.join(upload_folder, cv.filename)
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                    except Exception:
                        pass  # Ignore file deletion errors
            CV.query.filter_by(user_id=user_id).delete()
            if profile:
                db.session.delete(profile)
            db.session.delete(user)
            db.session.commit()
            flash(f'Student profile and all associated data have been deleted.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error deleting student profile. Please try again.', 'danger')
        return redirect(url_for('employer_dashboard'))

    @app.route('/employer/delete_cv/<int:cv_id>', methods=['POST'])
    @login_required
    def employer_delete_cv(cv_id):
        if current_user.role != 'employer':
            flash('Access denied. Employers only.', 'danger')
            return redirect(url_for('login'))
        try:
            cv = CV.query.get(cv_id)
            if not cv:
                flash('CV not found.', 'danger')
                return redirect(url_for('employer_dashboard'))
            user_id = cv.user_id
            upload_folder = current_app.config['UPLOAD_FOLDER']
            filepath = os.path.join(upload_folder, cv.filename)
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass  # Ignore file deletion errors
            db.session.delete(cv)
            db.session.commit()
            flash('CV deleted successfully.', 'success')
            return redirect(url_for('employer_view_profile', user_id=user_id))
        except Exception as e:
            db.session.rollback()
            flash('Error deleting CV. Please try again.', 'danger')
            return redirect(url_for('employer_dashboard'))

    @app.route('/employer/details')
    @login_required
    def employer_details():
        if current_user.role != 'employer':
            flash('Access denied. Employers only.', 'danger')
            return redirect(url_for('login'))
            
        employer_info = {
            "company_name": "Your Company Name Here",
            "contact_email": "contact@yourcompany.com",
            "instructions": "Please use these details to contact us or access employer resources."
        }
        return render_template('employer/details.html', employer_info=employer_info)
    
    

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500

    # Create tables
    with app.app_context():
        db.create_all()
        try:
            db.create_all()
            print("Database tables created successfully!")
            
            # Test database connection
            test_user = User.query.first()
            print(f"Database connection test: {test_user is not None or 'No users yet'}")
            
        except Exception as e:
            print(f"Database error: {e}")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host='127.0.0.1', port=5000)