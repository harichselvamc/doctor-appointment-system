from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, make_response
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import re
import hashlib
import os
from flask import Flask, jsonify, send_file, redirect, url_for, flash
from bson.objectid import ObjectId
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from functools import wraps
from functools import wraps
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, make_response, jsonify
app = Flask(__name__)
app.secret_key = os.urandom(24)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017")
db = client["appointment_system"]

# Collections
patients = db["patients"]
doctors = db["doctors"]
appointments = db["appointments"]
messages = db["messages"]
emergency_cases = db["emergency_cases"]
# Add wards collection
wards = db["wards"]

# Initialize some sample wards if empty
if wards.count_documents({}) == 0:
    wards.insert_many([
        {"name": "General Ward", "capacity": 20, "available": 20, "price_per_day": 1000},
        {"name": "Semi-Private Ward", "capacity": 10, "available": 10, "price_per_day": 2000},
        {"name": "Private Ward", "capacity": 5, "available": 5, "price_per_day": 5000},
        {"name": "ICU", "capacity": 8, "available": 8, "price_per_day": 10000}
    ])
# Initialize admin account if not exists
if db.admin.count_documents({}) == 0:
    admin_password = hashlib.sha256("adminpassword".encode()).hexdigest()
    db.admin.insert_one({"username": "admin", "password": admin_password})

# Login decorators
def login_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                flash('Please login to access this page', 'danger')
                return redirect(url_for('index'))
            if session['role'] != role:
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
# Login decorator for admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Login decorator for doctor
def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'doctor':
            flash('Doctor access required', 'danger')
            return redirect(url_for('doctor_login'))
        return f(*args, **kwargs)
    return decorated_function
# Routes
@app.route('/')
def index():
    doctor_list = list(doctors.find())
    return render_template('index.html', doctors=doctor_list)

@app.route('/emergency', methods=['GET', 'POST'])
def emergency():
    if request.method == 'POST':
        try:
            name = request.form['name']
            gender = request.form['gender']
            blood_group = request.form['blood_group']
            guardian_name = request.form['guardian_name']
            guardian_phone = request.form['guardian_phone']
            doctor_id = request.form.get('doctor_id', '')
            emergency_details = request.form['emergency_details']
            
            doctor = None
            if doctor_id:
                doctor = doctors.find_one({'_id': ObjectId(doctor_id)})
            
            emergency_id = emergency_cases.insert_one({
                'name': name,
                'gender': gender,
                'blood_group': blood_group,
                'guardian_name': guardian_name,
                'guardian_phone': guardian_phone,
                'doctor_id': doctor_id,
                'doctor_name': doctor['name'] if doctor else 'Any Available Doctor',
                'department': doctor['department'] if doctor else 'Emergency',
                'emergency_details': emergency_details,
                'created_on': datetime.now(),
                'status': 'pending'
            }).inserted_id
            
            appointments.insert_one({
                'patient_name': name,
                'doctor_id': doctor_id,
                'doctor_name': doctor['name'] if doctor else 'Emergency Team',
                'department': doctor['department'] if doctor else 'Emergency',
                'fees': 0,
                'date': datetime.now().strftime('%Y-%m-%d'),
                'time': datetime.now().strftime('%H:%M'),
                'status': 'emergency',
                'remarks': emergency_details,
                'prescription': '',
                'created_on': datetime.now(),
                'deleted': False,
                'deleted_by': '',
                'is_emergency': True,
                'emergency_id': str(emergency_id)
            })
            
            flash('Emergency case registered successfully!', 'success')
            return redirect(url_for('index'))
        
        except Exception as e:
            flash(f'Error processing emergency: {str(e)}', 'danger')
            return redirect(url_for('index'))
    
    doctor_list = list(doctors.find())
    return render_template('index.html', doctors=doctor_list)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        message = request.form['message']
        
        messages.insert_one({
            'name': name,
            'email': email,
            'phone': phone,
            'message': message,
            'date': datetime.now()
        })
        
        flash('Message sent successfully!', 'success')
        return redirect(url_for('index'))
    
    doctor_list = list(doctors.find())
    return render_template('index.html', doctors=doctor_list)

# Patient Routes
@app.route('/patient/register', methods=['GET', 'POST'])
def patient_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        age = request.form['age']
        height = request.form['height']
        weight = request.form['weight']
        blood_group = request.form['blood_group']
        allergies = request.form['allergies']
        previous_health_issues = request.form['previous_health_issues']
        smoking = 'smoking' in request.form
        drinking = 'drinking' in request.form
        
        if patients.find_one({'email': email}):
            flash('Email already registered', 'danger')
            return redirect(url_for('patient_register'))
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        patients.insert_one({
            'name': name,
            'email': email,
            'password': hashed_password,
            'phone': phone,
            'age': age,
            'height': height,
            'weight': weight,
            'blood_group': blood_group,
            'allergies': allergies,
            'previous_health_issues': previous_health_issues,
            'smoking': smoking,
            'drinking': drinking,
            'registered_on': datetime.now()
        })
        
        flash('Registration successful! Please login', 'success')
        return redirect(url_for('index'))
    
    doctor_list = list(doctors.find())
    return render_template('index.html', doctors=doctor_list)
@app.route('/doctor/prescription/<appointment_id>', methods=['GET'])
@login_required('doctor')
def doctor_view_prescription(appointment_id):
    try:
        # Validate appointment ID format
        if not ObjectId.is_valid(appointment_id):
            return jsonify({'error': 'Invalid appointment ID'}), 400
        
        appointment = appointments.find_one({
            '_id': ObjectId(appointment_id),
            'doctor_id': session['id']  # Ensure doctor only sees their own appointments
        })
        
        if not appointment:
            return jsonify({'error': 'Appointment not found or unauthorized access'}), 404
        
        # Prepare response data
        response_data = {
            'patient_name': appointment.get('patient_name', ''),
            'date': appointment.get('date', ''),
            'time': appointment.get('time', ''),
            'status': appointment.get('status', ''),
            'prescription': appointment.get('prescription', ''),
            'remarks': appointment.get('remarks', ''),
            'department': appointment.get('department', '')
        }
        
        return jsonify(response_data), 200
    
    except Exception as e:
        app.logger.error(f"Error fetching prescription: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
@app.route('/patient/login', methods=['POST'])
def patient_login():
    email = request.form['email']
    password = request.form['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    patient = patients.find_one({'email': email, 'password': hashed_password})
    
    if patient:
        session['logged_in'] = True
        session['role'] = 'patient'
        session['email'] = email
        session['name'] = patient['name']
        session['id'] = str(patient['_id'])
        flash('Login successful!', 'success')
        return redirect(url_for('patient_dashboard'))
    else:
        flash('Invalid login credentials', 'danger')
        return redirect(url_for('index'))

@app.route('/patient/dashboard')
@login_required('patient')
def patient_dashboard():
    # Get patient appointments
    patient_appointments = list(appointments.find({
        'patient_id': session['id']
    }).sort('date', -1).limit(50))
    
    # Get current admission if any
    current_admission = appointments.find_one({
        'patient_id': session['id'],
        'is_admitted': True,
        'admission_details.status': 'admitted'
    })
    
    # Get admission history
    admission_history = list(appointments.find({
        'patient_id': session['id'],
        'is_admitted': True,
        'admission_details.status': 'discharged'
    }).sort('admission_details.discharge_date', -1).limit(10))
    
    # Get doctor list for booking
    doctor_list = list(doctors.find())
    
    return render_template('patient_dashboard.html', 
                         appointments=patient_appointments,
                         doctors=doctor_list,
                         current_admission=current_admission,
                         admission_history=admission_history)

@app.route('/patient/book_appointment', methods=['POST'])
@login_required('patient')
def book_appointment():
    doctor_id = request.form['doctor_id']
    appointment_date = request.form['appointment_date']
    appointment_time = request.form['appointment_time']
    doctor = doctors.find_one({'_id': ObjectId(doctor_id)})
    
    # Make sure to include patient_id in the appointment
    appointments.insert_one({
        'patient_id': session['id'],  # This is crucial
        'patient_name': session['name'],
        'doctor_id': doctor_id,
        'doctor_name': doctor['name'],
        'department': doctor['department'],
        'fees': doctor['consultancy_fees'],
        'date': appointment_date,
        'time': appointment_time,
        'status': 'scheduled',
        'remarks': '',
        'prescription': '',
        'created_on': datetime.now(),
        'deleted': False,
        'deleted_by': '',
        'is_admitted': False  # Add this field
    })
    
    flash('Appointment booked successfully!', 'success')
    return redirect(url_for('patient_dashboard'))
@app.route('/patient/delete_appointment/<appointment_id>')
@login_required('patient')
def patient_delete_appointment(appointment_id):
    appointments.update_one(
        {'_id': ObjectId(appointment_id)},
        {'$set': {'deleted': True, 'deleted_by': session['name'], 'status': 'cancelled'}}
    )
    flash('Appointment cancelled successfully!', 'success')
    return redirect(url_for('patient_dashboard'))

@app.route('/patient/prescription/<appointment_id>', methods=['GET'])
@login_required('patient')
def view_prescription(appointment_id):
    appointment = appointments.find_one({
        '_id': ObjectId(appointment_id),
        'patient_id': session['id']
    })
    
    if not appointment:
        flash('Prescription not found', 'danger')
        return redirect(url_for('patient_dashboard'))
    
    return render_template('view_prescription.html', 
                         prescription=appointment.get('prescription', ''),
                         appointment=appointment)

@app.route('/patient/prescription/<appointment_id>/download', methods=['GET'])
@login_required('patient')
def download_prescription(appointment_id):
    try:
        appointment = appointments.find_one({
            '_id': ObjectId(appointment_id),
            '$or': [
                {'patient_id': session['id']},  # Patient can download their own
                {'doctor_id': session['id']}    # Doctor can download their patient's
            ]
        })
        
        if not appointment or not appointment.get('prescription'):
            flash('Prescription not found', 'danger')
            return redirect(url_for('patient_dashboard' if session['role'] == 'patient' else 'doctor_dashboard'))
        
        # Create PDF
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        
        # Add content to PDF
        p.drawString(100, 750, "Medical Prescription")
        p.drawString(100, 730, f"Patient: {appointment['patient_name']}")
        p.drawString(100, 710, f"Doctor: {appointment.get('doctor_name', '')}")
        p.drawString(100, 690, f"Date: {appointment['date']}")
        p.drawString(100, 670, "Prescription:")
        
        # Handle multi-line prescription
        y = 650
        for line in appointment['prescription'].split('\n'):
            p.drawString(100, y, line)
            y -= 20
        
        p.showPage()
        p.save()
        
        # Prepare response
        buffer.seek(0)
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = \
            f'attachment; filename=prescription_{appointment_id}.pdf'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Error generating prescription PDF: {str(e)}")
        flash('Error generating prescription', 'danger')
        return redirect(url_for('patient_dashboard' if session['role'] == 'patient' else 'doctor_dashboard'))
@app.route('/patient/logout')
def patient_logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# Doctor Routes
@app.route('/doctor/login', methods=['POST'])
def doctor_login():
    email = request.form['email']
    password = request.form['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    doctor = doctors.find_one({'email': email, 'password': hashed_password})
    
    if doctor:
        session['logged_in'] = True
        session['role'] = 'doctor'
        session['email'] = email
        session['name'] = doctor['name']
        session['id'] = str(doctor['_id'])  # Ensure this is stored as string
        flash('Login successful!', 'success')
        return redirect(url_for('doctor_dashboard'))
    else:
        flash('Invalid login credentials', 'danger')
        return redirect(url_for('index'))
@app.route('/doctor/dashboard')
@login_required('doctor')
def doctor_dashboard():
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Convert doctor_id to string for comparison
        doctor_id_str = session['id']
        
        # Get today's appointments
        doctor_appointments = list(appointments.find({
            'doctor_id': doctor_id_str,  # Match the string format
            'deleted': False,
            'date': today
        }).sort([('is_emergency', -1), ('time', 1)]))
        
        # Get appointment history
        appointment_history = list(appointments.find({
            'doctor_id': doctor_id_str,
            'status': 'attended',
            'deleted': False
        }).sort('date', -1).limit(50))
        
        # Get current admissions
        current_admissions = list(appointments.find({
            'doctor_id': doctor_id_str,
            'is_admitted': True,
            'admission_details.status': 'admitted',
            'deleted': False
        }).sort('admission_details.admitted_on', -1))
        
        # Get admission history
        admission_history = list(appointments.find({
            'doctor_id': doctor_id_str,
            'is_admitted': True,
            'admission_details.status': 'discharged',
            'deleted': False
        }).sort('admission_details.discharge_date', -1).limit(50))
        
        # Get available wards
        available_wards = list(wards.find({'available': {'$gt': 0}}))
        
        return render_template('doctor_dashboard.html', 
                            appointments=doctor_appointments,
                            appointment_history=appointment_history,
                            current_admissions=current_admissions,
                            admission_history=admission_history,
                            available_wards=available_wards)
    
    except Exception as e:
        app.logger.error(f"Error in doctor dashboard: {str(e)}")
        flash('Error loading dashboard data', 'danger')
        return redirect(url_for('index'))
@app.route('/doctor/admit_patient', methods=['POST'])
@doctor_required
def admit_patient():
    try:
        data = request.get_json()
        appointment_id = data['appointment_id']
        ward_id = data['ward_id']
        reason = data['reason']
        days = int(data['days'])
        notes = data.get('notes', '')
        
        appointment = appointments.find_one({'_id': ObjectId(appointment_id)})
        ward = wards.find_one({'_id': ObjectId(ward_id)})
        
        if not appointment or not ward:
            return jsonify({'success': False, 'message': 'Invalid appointment or ward'}), 400
        
        if ward['available'] <= 0:
            return jsonify({'success': False, 'message': 'Selected ward is full'}), 400
        
        # Update appointment with admission details
        appointments.update_one(
            {'_id': ObjectId(appointment_id)},
            {'$set': {
                'is_admitted': True,
                'admission_details': {
                    'ward_id': ward_id,
                    'ward_name': ward['name'],
                    'reason': reason,
                    'days': days,
                    'notes': notes,
                    'admitted_on': datetime.now(),
                    'discharge_date': None,
                    'total_charges': ward['price_per_day'] * days,
                    'status': 'admitted'
                }
            }}
        )
        
        # Update ward availability
        wards.update_one(
            {'_id': ObjectId(ward_id)},
            {'$inc': {'available': -1}}
        )
        
        return jsonify({
            'success': True,
            'message': 'Patient admitted successfully!',
            'admission': {
                'ward_name': ward['name'],
                'reason': reason,
                'days': days,
                'total_charges': ward['price_per_day'] * days
            }
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
@app.route('/doctor/discharge_patient', methods=['POST'])
@login_required('doctor')
def discharge_patient():
    try:
        data = request.get_json()
        appointment_id = data['appointment_id']
        discharge_notes = data['discharge_notes']
        
        appointment = appointments.find_one({'_id': ObjectId(appointment_id)})
        if not appointment or not appointment.get('is_admitted'):
            return jsonify({'success': False, 'message': 'Patient not admitted'}), 400
        
        # Update appointment
        appointments.update_one(
            {'_id': ObjectId(appointment_id)},
            {'$set': {
                'admission_details.status': 'discharged',
                'admission_details.discharge_date': datetime.now(),
                'admission_details.discharge_notes': discharge_notes
            }}
        )
        
        # Update ward availability
        wards.update_one(
            {'_id': ObjectId(appointment['admission_details']['ward_id'])},
            {'$inc': {'available': 1}}
        )
        
        return jsonify({'success': True, 'message': 'Patient discharged successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/doctor/update_appointment/<appointment_id>', methods=['POST'])
@login_required('doctor')
def update_appointment(appointment_id):
    try:
        status = request.form['status']
        remarks = request.form['remarks']
        prescription = request.form.get('prescription', '')
        
        update_data = {
            'status': status,
            'remarks': remarks,
            'prescription': prescription
        }
        
        # Handle admission if checkbox was checked
        if 'admit_patient' in request.form and request.form['admit_patient'] == 'on':
            ward_id = request.form['ward_id']
            ward = wards.find_one({'_id': ObjectId(ward_id)})
            
            if not ward or ward['available'] <= 0:
                flash('Selected ward is not available', 'danger')
                return redirect(url_for('doctor_dashboard'))
            
            update_data['is_admitted'] = True
            update_data['admission_details'] = {
                'ward_id': ward_id,
                'ward_name': ward['name'],
                'reason': request.form['reason'],
                'days': int(request.form['days']),
                'notes': request.form.get('admission_notes', ''),
                'admitted_on': datetime.now(),
                'status': 'admitted',
                'total_charges': ward['price_per_day'] * int(request.form['days'])
            }
            
            # Update ward availability
            wards.update_one(
                {'_id': ObjectId(ward_id)},
                {'$inc': {'available': -1}}
            )
        
        appointments.update_one(
            {'_id': ObjectId(appointment_id)},
            {'$set': update_data}
        )
        
        flash('Appointment updated successfully!', 'success')
        return redirect(url_for('doctor_dashboard'))
    
    except Exception as e:
        flash(f'Error updating appointment: {str(e)}', 'danger')
        return redirect(url_for('doctor_dashboard'))

@app.route('/doctor/delete_appointment/<appointment_id>')
@login_required('doctor')
def doctor_delete_appointment(appointment_id):
    appointments.update_one(
        {'_id': ObjectId(appointment_id)},
        {'$set': {'deleted': True, 'deleted_by': session['name'], 'status': 'cancelled'}}
    )
    flash('Appointment cancelled successfully!', 'success')
    return redirect(url_for('doctor_dashboard'))

@app.route('/doctor/logout')
def doctor_logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# Admin Routes
@app.route('/admin/login', methods=['POST'])
def admin_login():
    username = request.form.get('username')
    password = request.form.get('password')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    admin = db.admin.find_one({'username': username, 'password': hashed_password})
    
    if admin:
        session['logged_in'] = True
        session['role'] = 'admin'
        session['username'] = username
        flash('Login successful!', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid login credentials', 'danger')
        return redirect(url_for('index'))

@app.route('/admin/dashboard')
@login_required('admin')
def admin_dashboard():
    doctor_count = doctors.count_documents({})
    patient_count = patients.count_documents({})
    appointment_count = appointments.count_documents({})
    message_count = messages.count_documents({})
    emergency_count = emergency_cases.count_documents({})
    
    doctor_list = list(doctors.find())
    patient_list = list(patients.find())
    appointment_list = list(appointments.find().sort([('is_emergency', -1), ('date', -1)]))
    message_list = list(messages.find().sort('date', -1))
    emergency_list = list(emergency_cases.find().sort('created_on', -1))
    
    # Get all current admissions
    current_admissions = list(appointments.find({
        'is_admitted': True,
        'admission_details.status': 'admitted'
    }))
    
    # Get ward status
    ward_status = list(wards.find())
    
    return render_template('admin_dashboard.html',
                        doctor_count=doctor_count,
                        patient_count=patient_count,
                        appointment_count=appointment_count,
                        message_count=message_count,
                        emergency_count=emergency_count,
                        doctors=doctor_list,
                        patients=patient_list,
                        appointments=appointment_list,
                        messages=message_list,
                        emergencies=emergency_list,
                        current_admissions=current_admissions,
                        ward_status=ward_status)
@app.route('/get_admission_details/<appointment_id>')
@login_required
def get_admission_details(appointment_id):
    try:
        appointment = appointments.find_one({'_id': ObjectId(appointment_id)})
        
        if not appointment or not appointment.get('is_admitted'):
            return jsonify({'success': False, 'message': 'No admission record found'}), 404
        
        # Check permissions
        if session['role'] == 'patient' and appointment['patient_id'] != session['id']:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
        
        if session['role'] == 'doctor' and appointment['doctor_id'] != session['id']:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
        
        return jsonify({
            'success': True,
            'admission': appointment['admission_details']
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/admin/add_doctor', methods=['POST'])
@login_required('admin')
def add_doctor():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    department = request.form['department']
    consultancy_fees = request.form['consultancy_fees']
    
    if password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if doctors.find_one({'email': email}):
        flash('Email already registered', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    doctors.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password,
        'department': department,
        'consultancy_fees': consultancy_fees,
        'created_on': datetime.now()
    })
    
    flash('Doctor added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_doctor/<doctor_id>')
@login_required('admin')
def delete_doctor(doctor_id):
    doctors.delete_one({'_id': ObjectId(doctor_id)})
    appointments.update_many(
        {'doctor_id': doctor_id},
        {'$set': {'deleted': True, 'deleted_by': 'admin', 'status': 'cancelled'}}
    )
    flash('Doctor deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_patient/<patient_id>')
@login_required('admin')
def delete_patient(patient_id):
    patients.delete_one({'_id': ObjectId(patient_id)})
    appointments.update_many(
        {'patient_id': patient_id},
        {'$set': {'deleted': True, 'deleted_by': 'admin', 'status': 'cancelled'}}
    )
    flash('Patient deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_message/<message_id>')
@login_required('admin')
def delete_message(message_id):
    messages.delete_one({'_id': ObjectId(message_id)})
    flash('Message deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_emergency/<emergency_id>')
@login_required('admin')
def delete_emergency(emergency_id):
    emergency_cases.delete_one({'_id': ObjectId(emergency_id)})
    appointments.update_many(
        {'emergency_id': emergency_id},
        {'$set': {'deleted': True, 'deleted_by': 'admin', 'status': 'cancelled'}}
    )
    flash('Emergency case deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))
@app.route('/admin/prescription/<appointment_id>/download')
@admin_required
def admin_download_prescription(appointment_id):
    try:
        if not ObjectId.is_valid(appointment_id):
            flash('Invalid appointment ID', 'danger')
            return redirect(url_for('admin_dashboard'))

        appointment = appointments.find_one({'_id': ObjectId(appointment_id)})
        
        if not appointment or not appointment.get('prescription'):
            flash('Prescription not found', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Create PDF
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        
        # Add content to PDF
        p.drawString(100, 750, "Medical Prescription (Admin Copy)")
        p.drawString(100, 730, f"Patient: {appointment['patient_name']}")
        p.drawString(100, 710, f"Doctor: {appointment.get('doctor_name', '')}")
        p.drawString(100, 690, f"Department: {appointment.get('department', '')}")
        p.drawString(100, 670, f"Date: {appointment.get('date', '')}")
        p.drawString(100, 650, "Prescription:")
        
        # Handle multi-line prescription
        y = 630
        for line in appointment['prescription'].split('\n'):
            p.drawString(100, y, line)
            y -= 20
        
        p.drawString(100, y-30, "Doctor Remarks:")
        p.drawString(100, y-50, appointment.get('remarks', 'No remarks provided'))
        
        p.showPage()
        p.save()
        
        # Prepare response
        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"prescription_{appointment_id}_admin.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        app.logger.error(f"Error generating prescription PDF: {str(e)}")
        flash('Error generating prescription', 'danger')
        return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)