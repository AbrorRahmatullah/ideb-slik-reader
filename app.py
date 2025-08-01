import os
import re
import time
import numpy as np
import pandas as pd
import json
import threading
import queue
import uuid
import traceback
import urllib
import shutil
import zipfile

from flask import Flask, make_response, request, render_template, redirect, url_for, flash, session, jsonify, send_file, has_request_context
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from io import BytesIO
from dateutil import parser

from config.database import get_db_connection
from functions.popup_notification import render_alert

app = Flask(__name__)
app.secret_key = 'supersecretkey'
bcrypt = Bcrypt(app)

# Configure session timeout to 10 minutes
app.permanent_session_lifetime = timedelta(minutes=30)

# Temporary storage for DataFrame
uploaded_data = None
uploaded_data_2 = None
uploaded_data_3 = None
uploaded_data_4 = None
uploaded_data_5 = None
uploaded_data_6 = None
uploaded_data_7 = None
uploaded_data_8 = None
uploaded_data_9 = None
uploaded_data_10 = None
uploaded_data_11 = None

data_available = False
flag = ''

active_facility_1 = None
active_facility_2 = None
active_facility_3 = None
active_facility_4 = None
active_facility_5 = None

closed_facility_1 = None
closed_facility_2 = None
closed_facility_3 = None
closed_facility_4 = None
closed_facility_5 = None

ALLOWED_EXTENSIONS = {'.txt'}
# Available flags
FLAGS = ["Individual", "Perusahaan"]
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_FILE_BIG_SIZE = 200 * 1024 * 1024  # 10MB
UPLOAD_BASE_DIR = "uploads"

# Create a global task queue and task results dictionary
task_queue = queue.Queue()
task_results = {}
task_progress = {}
served_final_status = {}
conn = get_db_connection()
cur = conn.cursor()

def try_parse_upload_date(uploadDate):
    # Coba format "29 July 2025, 16:26"
    try:
        return datetime.strptime(uploadDate, "%d %B %Y, %H:%M")
    except ValueError:
        pass

    # Coba format "2025-07-29 17:41:57"
    try:
        return datetime.strptime(uploadDate, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass

    # Coba format dari JS new Date().toLocaleString('id-ID') => "29/7/2025, 17.29.35"
    try:
        return datetime.strptime(uploadDate, "%d/%m/%Y, %H.%M.%S")
    except ValueError:
        pass

    raise ValueError(f"Format tanggal tidak dikenali: {uploadDate}")

# Tambahkan helper function
def is_allowed_file(filename, mimetype):
    return (
        os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS and
        mimetype == 'text/plain'
    )
    
def is_txt_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

# --- Utility Functions ---
def sanitize_folder_name(nama_file):
    """Konversi nama file menjadi nama folder yang valid"""
    return nama_file.lower().replace(" ", "_").replace("-", "_")

def ensure_upload_dir():
    """Pastikan direktori upload utama ada"""
    if not os.path.exists(UPLOAD_BASE_DIR):
        os.makedirs(UPLOAD_BASE_DIR)

def create_upload_folder(nama_file_upload):
    """Buat folder untuk upload session tertentu"""
    ensure_upload_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = sanitize_folder_name(nama_file_upload)
    folder_name = f"{folder_name}_{timestamp}"
    upload_path = os.path.join(UPLOAD_BASE_DIR, folder_name)
    
    os.makedirs(upload_path, exist_ok=True)
    return upload_path

def save_file_to_local(file_content, filename, upload_path):
    """Simpan file ke folder lokal"""
    file_path = os.path.join(upload_path, filename)
    with open(file_path, 'wb') as f:
        f.write(file_content)
    return file_path

# --- Check if file name exists ---
def check_filename_exists(namaFileUpload):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = "SELECT COUNT(*) FROM slik_uploader WHERE namaFileUpload = ?"
        cursor.execute(query, (namaFileUpload,))
        count = cursor.fetchone()[0]
        
        return count > 0
        
    except Exception as e:
        print(f"Error checking filename: {e}")
        traceback.print_exc()
        return False
    finally:
        cursor.close()
        conn.close()

def get_existing_filenames():
    """
    Fungsi untuk mengambil daftar nama file yang sudah ada
    Sesuaikan dengan struktur database/storage Anda
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT DISTINCT namaFileUpload FROM slik_uploader")
        result = cursor.fetchall()
        return [row[0] for row in result]
        
    except Exception as e:
        print(f"Error getting existing filenames: {e}")
        return []

# --- Alternative: Jika menggunakan Flask dengan flash message ---
def save_file_metadata_to_db_flask(periodeData, namaFileUpload, uploadFolderPath, username, fullname, roleAccess, uploadDate):
    try:
        
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
            INSERT INTO slik_uploader (periodeData, namaFileUpload, uploadFolderPath, username, fullname, roleAccess, uploadDate)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(query, (periodeData, namaFileUpload, uploadFolderPath, username, fullname, roleAccess, uploadDate))
        conn.commit()
        
        return True

    except Exception as e:
        print(f"Error saving to DB: {e}")
        traceback.print_exc()
    finally:
        cursor.close()
        conn.close()

# --- Background Worker ---
def process_files_worker():
    while True:
        try:
            task_id, files, user_info = task_queue.get(timeout=1)
        except queue.Empty:
            continue

        conn = None
        validation_failed = False

        try:
            bulan_dict = {
                1: "Januari", 2: "Februari", 3: "Maret", 4: "April",
                5: "Mei", 6: "Juni", 7: "Juli", 8: "Agustus",
                9: "September", 10: "Oktober", 11: "November", 12: "Desember"
            }

            nama_file_upload = user_info.get("nama_file")
            upload_folder_path = create_upload_folder(nama_file_upload)

            periode_data = None
            uploaded_files = []

            session_npwp = None
            session_identitas = None

            for file_data in files:
                filename = secure_filename(file_data['filename'])
                mimetype = file_data.get('mimetype', 'text/plain')
                if not is_allowed_file(filename, mimetype):
                    raise ValueError(f"File {filename} bukan .txt atau tipe MIME salah.")

                save_file_to_local(file_data['content'], filename, upload_folder_path)

                uploaded_files.append(FileStorage(
                    stream=BytesIO(file_data['content']),
                    filename=filename,
                    name='file',
                    content_type=mimetype
                ))

            # Loop untuk validasi semua file dulu
            for idx, uploaded_file in enumerate(uploaded_files):
                file_content = uploaded_file.stream.read()
                file_processed = False

                for encoding in ['utf-8', 'latin-1', 'utf-16', 'ascii']:
                    try:
                        content = re.sub(r'[^\x20-\x7E\t\r\n]', '', file_content.decode(encoding))
                        data = json.loads(content)

                        if 'perusahaan' in data:
                            obj = data['perusahaan']
                            ident_key = 'npwp'
                        elif 'individual' in data:
                            obj = data['individual']
                            ident_key = 'noIdentitas'
                        else:
                            continue

                        posisi = obj.get('posisiDataTerakhir', '')
                        ident = obj.get('parameterPencarian', {}).get(ident_key, '')

                        if not posisi or not ident:
                            error_msg = f"File {uploaded_file.filename} tidak memiliki data posisi atau identitas."
                            task_results[task_id] = {
                                'status': 'error',
                                'message': error_msg,
                                'error_type': 'validation_error'
                            }
                            task_progress[task_id].update({
                                'status': 'error',
                                'progress': 100,
                                'error_type': 'validation_error',
                                'message': error_msg
                            })
                            
                            # ✅ PERBAIKAN: Cleanup folder dan mark task done
                            try:
                                if os.path.exists(upload_folder_path):
                                    shutil.rmtree(upload_folder_path)
                            except Exception as cleanup_error:
                                app.logger.error(f"Error hapus folder: {cleanup_error}")
                            
                            # ✅ PERBAIKAN: Jangan return, biarkan flow normal untuk cleanup
                            break  # keluar dari loop encoding

                        if ident_key == 'npwp':
                            if session_npwp is None:
                                session_npwp = ident
                            elif session_npwp != ident:
                                error_msg = f"NPWP file ke-{idx+1} tidak konsisten dengan file pertama."
                                task_results[task_id] = {
                                    'status': 'error',
                                    'message': error_msg,
                                    'error_type': 'validation_error'
                                }
                                task_progress[task_id].update({
                                    'status': 'error',
                                    'progress': 100,
                                    'error_type': 'validation_error',
                                    'message': error_msg
                                })
                                
                                # ✅ PERBAIKAN: Cleanup folder
                                try:
                                    if os.path.exists(upload_folder_path):
                                        shutil.rmtree(upload_folder_path)
                                except Exception as cleanup_error:
                                    app.logger.error(f"Error hapus folder: {cleanup_error}")
                                
                                # ✅ PERBAIKAN: Set flag untuk keluar dari loop utama
                                validation_failed = True
                                break  # keluar dari loop encoding
                        else:
                            if session_identitas is None:
                                session_identitas = ident
                            elif session_identitas != ident:
                                error_msg = f"Identitas file ke-{idx+1} tidak konsisten dengan file pertama."
                                task_results[task_id] = {
                                    'status': 'error',
                                    'message': error_msg,
                                    'error_type': 'validation_error'
                                }
                                task_progress[task_id].update({
                                    'status': 'error',
                                    'progress': 100,
                                    'error_type': 'validation_error',
                                    'message': error_msg
                                })
                                
                                try:
                                    if os.path.exists(upload_folder_path):
                                        shutil.rmtree(upload_folder_path)
                                except Exception as cleanup_error:
                                    app.logger.error(f"Error hapus folder: {cleanup_error}")
                                
                                # task_queue.task_done()
                                # return
                                validation_failed = True
                                break

                        # Parse periode data dari posisi
                        date_obj = datetime.strptime(posisi, "%Y%m")
                        periode_data = f"{bulan_dict[date_obj.month]} {date_obj.year}"
                        if task_id in task_progress and 'temp_metadata' in task_progress[task_id]:
                            task_progress[task_id]['temp_metadata']['periodeData'] = periode_data

                        file_processed = True
                        break

                    except (json.JSONDecodeError, ValueError, Exception) as e:
                        continue

                # Reset stream position untuk file berikutnya
                uploaded_file.stream.seek(0)
                
                if validation_failed:
                    break

                # Jika tidak ada encoding yang berhasil
                if not file_processed:
                    error_msg = f"Gagal memproses file: {uploaded_file.filename}"
                    
                    task_results[task_id] = {
                        "status": "error",
                        "message": error_msg,
                        "error_type": "validation_error"
                    }
                    
                    task_progress[task_id].update({
                        'status': 'error',
                        'progress': 100,
                        'error_type': 'validation_error',
                        'message': error_msg
                    })
                    
                    app.logger.error(f"[{task_id}] {error_msg}")
                    
                    try:
                        if os.path.exists(upload_folder_path):
                            shutil.rmtree(upload_folder_path)
                    except Exception as cleanup_error:
                        app.logger.error(f"Error hapus folder: {cleanup_error}")
                    
                    validation_failed = True
                    break
                
            if validation_failed:
                # Task sudah di-set sebagai error di task_results dan task_progress
                # Langsung mark task done dan return
                task_queue.task_done()
                return
            
            # Validasi selesai, baru insert metadata 1x
            uploaded_at = datetime.now()

            if not periode_data:
                periode_data = "Periode Tidak Dikenal"
                
            save_file_metadata_to_db_flask(
                periodeData=periode_data,
                namaFileUpload=nama_file_upload,
                uploadFolderPath=upload_folder_path,
                username=user_info.get("username"),
                fullname=user_info.get("fullname"),
                roleAccess=user_info.get("role_access"),
                uploadDate=uploaded_at
            )

            if task_id in task_progress:
                task_progress[task_id]['progress'] = 10

            result = process_uploaded_files(task_id, files, uploaded_files, user_info, uploaded_at)

            if isinstance(result, dict) and result.get("error"):
                if task_id in task_progress:
                    task_progress[task_id]['status'] = 'error'
                    task_progress[task_id]['progress'] = 100
                    task_progress[task_id]['timestamp'] = time.time()
                    task_progress[task_id]['message'] = result.get("message", "Terjadi kesalahan.")
                    task_progress[task_id]['error_type'] = result.get("error_type", "validation_error")

                task_results[task_id] = {
                    "status": "error",
                    "message": result.get("message", "Terjadi kesalahan."),
                    "error_type": result.get("error_type", "validation_error"),
                    "redirect_url": result.get("redirect_url", "/upload-big-size")
                }

                try:
                    if os.path.exists(upload_folder_path):
                        shutil.rmtree(upload_folder_path)
                except Exception as cleanup_error:
                    app.logger.error(f"Error hapus folder: {cleanup_error}")

                app.logger.error(f"[{task_id}] Gagal: {result.get('message')}")

            else:
                result['upload_folder_path'] = upload_folder_path
                task_results[task_id] = {"status": "completed", "result": result}

                if task_id in task_progress:
                    task_progress[task_id]['status'] = 'completed'
                    task_progress[task_id]['progress'] = 100
                    task_progress[task_id]['timestamp'] = time.time()

                app.logger.info(f"[{task_id}] Selesai diproses.")

        except Exception as e:
            error_msg = f"Error tidak terduga: {str(e)}"
            
            task_results[task_id] = {
                "status": "error",
                "message": error_msg,
                "error_type": "system_error"
            }
            
            task_progress[task_id].update({
                'status': 'error',
                'progress': 100,
                'error_type': 'system_error',
                'message': error_msg
            })
            
            app.logger.error(f"[{task_id}] {error_msg}")
            
            try:
                if os.path.exists(upload_folder_path):
                    shutil.rmtree(upload_folder_path)
            except Exception as cleanup_error:
                app.logger.error(f"Error hapus folder: {cleanup_error}")

        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
            if not validation_failed:
                task_queue.task_done()

# Jalankan 4 worker thread
for _ in range(4):
    threading.Thread(target=process_files_worker, daemon=True).start()

def escape_sql(val):
    """Mencegah SQL Injection dengan mengganti ' menjadi ''."""
    return val.replace("'", "''") if isinstance(val, str) else val

# --- Download Functions ---
def create_zip_from_folder(folder_path, zip_name=None):
    """Buat file ZIP dari semua file dalam folder"""
    if not os.path.exists(folder_path):
        raise FileNotFoundError(f"Folder {folder_path} tidak ditemukan")
    
    if zip_name is None:
        zip_name = f"{os.path.basename(folder_path)}.zip"
    
    # Buat ZIP file di memory
    memory_file = BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                # Tambahkan file ke ZIP dengan path relatif
                arcname = os.path.relpath(file_path, folder_path)
                zipf.write(file_path, arcname)
    
    memory_file.seek(0)
    return memory_file, zip_name

# Route untuk mengecek nama file
@app.route('/check-filename', methods=['POST'])
def check_filename():
    try:
        data = request.get_json()
        nama_file = data.get('nama_file', '').strip()
        
        if not nama_file:
            return jsonify({'exists': False, 'message': 'Nama file tidak boleh kosong'})
        
        # Cek apakah nama file sudah ada di database
        exists = check_filename_exists(nama_file)
        
        return jsonify({
            'exists': exists,
            'message': 'Nama file sudah ada' if exists else 'Nama file tersedia'
        })
        
    except Exception as e:
        print(f"Error checking filename: {e}")
        return jsonify({'exists': False, 'message': 'Error checking filename'}), 500

@app.route('/list_files')
def list_files():
    return render_template('list_file_uploads.html')

# --- Get Upload List ---
@app.route('/list_uploads')
def list_uploads():
    """List semua upload dengan info folder path dan tanggal"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Menggunakan uploadFolderPath sebagai pengganti fileContentBase64
        cursor.execute("""
            SELECT id, namaFileUpload, uploadFolderPath, uploadDate, username, periodeData
            FROM slik_uploader 
            ORDER BY uploadDate DESC
        """)
        
        uploads = []
        for row in cursor.fetchall():
            upload_id, nama_file_upload, folder_path, upload_date, username, periode_data = row
            
            # Check if folder still exists and count files
            folder_exists = os.path.exists(folder_path) if folder_path else False
            file_count = 0
            
            if folder_exists:
                try:
                    file_count = len([f for f in os.listdir(folder_path) 
                                    if os.path.isfile(os.path.join(folder_path, f))])
                except:
                    file_count = 0
            
            # Format tanggal untuk display yang lebih baik
            formatted_date = upload_date
            if upload_date:
                try:
                    # Jika upload_date adalah string, parse dulu
                    if isinstance(upload_date, str):
                        from datetime import datetime
                        date_obj = datetime.strptime(upload_date, '%Y-%m-%d %H:%M:%S')
                        formatted_date = date_obj.isoformat()
                    else:
                        # Jika sudah datetime object
                        formatted_date = upload_date.isoformat()
                except:
                    formatted_date = str(upload_date)
            
            uploads.append({
                "id": upload_id,
                "nama_file": nama_file_upload,  # Sesuai dengan HTML template
                "folder_path": folder_path,
                "file_count": file_count,
                "upload_date": formatted_date,
                "username": username,
                "periode": periode_data,  # Sesuai dengan HTML template
                "folder_exists": folder_exists,
                "download_url": f"/download_upload/{upload_id}" if folder_exists else None
            })
            
        return jsonify(uploads)
        
    except Exception as e:
        print(f"Error listing uploads: {e}")
        return jsonify({"error": "Terjadi kesalahan"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# --- Flask Routes untuk Download ---
@app.route('/download_upload')
def download_upload_zip():
    """Download semua file dalam satu upload session sebagai ZIP"""
    periodeData = request.args.get('periodeData')
    username = session.get('username')
    namaFileUpload = request.args.get('namaFileUpload')
    uploadDate = request.args.get('uploadDate')
    
    print({
        'periodeData':periodeData,
        'uploadDate':uploadDate,
        'username':username,
        'namaFileUpload':namaFileUpload
    })

    downloadType = "File Upload TXT"
    downloadDate = datetime.now()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # FIX: Query hanya memiliki 5 parameter, bukan 7
            query = """
                INSERT INTO slik_download_logging (periodeData, namaFileUpload, downloadType, username, downloadDate)
                VALUES (?, ?, ?, ?, ?)
            """
            
            cursor.execute(query, (periodeData, namaFileUpload, downloadType, username, downloadDate))
            conn.commit()

        except Exception as e:
            print(f"Error saving to DB: {e}")
            traceback.print_exc()
        
        # Ambil info upload dari database (menggunakan uploadFolderPath)
        cursor.execute("""
            SELECT uploadFolderPath, namaFileUpload 
            FROM slik_uploader 
            WHERE periodeData = ? AND username = ? AND namaFileUpload = ?
        """, (periodeData, username, namaFileUpload))
        
        result = cursor.fetchone()
        
        if not result:
            return jsonify({"error": "Upload tidak ditemukan"}), 404
        
        upload_folder_path, nama_file_upload = result
        
        # Pastikan folder masih ada
        if not os.path.exists(upload_folder_path):
            return jsonify({"error": "File tidak ditemukan di server"}), 404
        
        # Buat ZIP file
        zip_file, zip_name = create_zip_from_folder(
            upload_folder_path, 
            f"{sanitize_folder_name(nama_file_upload)}.zip"
        )
        
        # Return ZIP file
        return send_file(
            zip_file,
            as_attachment=True,
            download_name=zip_name,
            mimetype='application/zip'
        )
        
    except Exception as e:
        print(f"Error downloading files: {e}")
        traceback.print_exc()
        return jsonify({"error": "Terjadi kesalahan saat mengunduh file"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        role_access = request.form['role_access']
        fullname = request.form['fullname']
        email = request.form['email']
        
        required_fields = ['username', 'password', 'password_confirm', 'role_access', 'fullname', 'email']
        data = {field: request.form[field] for field in required_fields}

        if not all(data.values()):
            return render_alert("Please fill the empty form!", 'register', username, fullname, email)

        if password != password_confirm:
            return render_alert("Passwords do not match.", 'register', username, fullname, email)
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Check if the username already exists
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            return render_alert("Username already exists.", 'register', username, fullname, email, role_access)
        
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_email = cur.fetchone()

        if existing_email:
            return render_alert("Email is already registered.", 'register', username, fullname, email, role_access)

        else:
            # Insert new user into the database
            cur.execute("INSERT INTO users (username, password_hash, role_access, fullname, email, created_date) VALUES (?, ?, ?, ?, ?, GETDATE())", (username, password_hash, role_access, fullname, email))
            conn.commit()
            return '''
                <script>
                    alert("User registered successfully.");
                    window.location.href = "{}";
                </script>
            '''.format(url_for('login'))


    return render_template('register.html')

# Login Route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        session['data_available'] = False
        
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch the hashed password from the database for the given username
        cur.execute("SELECT password_hash, role_access, fullname FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user and bcrypt.check_password_hash(user[0], password):
            fullname = user[2]
            session.permanent = True
            session['username'] = username
            session['fullname'] = fullname
            session['role_access'] = user[1]
            session['upload_done'] = True
            return redirect(url_for('upload_big_size_file'))
        else:
            flash("Invalid username or password.")
    
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        username = session['username']

        if new_password != confirm_password:
            # flash("New passwords do not match.")
            # return render_template('change_password.html')
            return '''
                <script>
                    alert("New passwords do not match.");
                    window.location.href = "/change_password"; // Redirect setelah alert
                </script>
            '''

        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch the current hashed password from the database
        cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if not user or not bcrypt.check_password_hash(user[0], current_password):
            # flash("Current password is incorrect.")
            # return render_template('change_password.html')
            return '''
                    <script>
                        alert("Current password is incorrect.");
                        window.location.href = "/change_password"; // Redirect setelah alert
                    </script>
                '''
        else:
            # Hash the new password and update the database
            new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cur.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password_hash, username))
            conn.commit()
            # flash("Password changed successfully.")
            # return render_template('upload.html')
            return '''
                <script>
                    alert("Password changed successfully.");
                    window.location.href = "/upload"; // Redirect setelah alert
                </script>
            '''
            
        cur.close()
        conn.close()

    return render_template('change_password.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

def insert_data(cursor, table_name, data_item, columns_to_remove=None, extra_columns=None):
    """
    Fungsi umum untuk menyisipkan data ke tabel tertentu dengan opsi metadata tambahan.
    """
    if not data_item:
        return
    
    try:
        # Filter kolom jika perlu
        filtered_item = data_item
        if columns_to_remove:
            if isinstance(data_item, dict):
                filtered_item = {k: v for k, v in data_item.items() if k not in columns_to_remove}
        
        # Penyesuaian key tertentu (khusus untuk tabel tertentu)
        if table_name == "slik_ringkasan_fasilitas" and "krediturBPR/S" in filtered_item:
            filtered_item["krediturBPR_S"] = filtered_item.pop("krediturBPR/S")
        
        # Tambahkan kolom tambahan
        if extra_columns:
            filtered_item.update(extra_columns)
        
        # Siapkan query
        columns = ', '.join(filtered_item.keys())
        placeholders = ', '.join(['?'] * len(filtered_item))
        values = tuple(filtered_item.values())

        query = f"""
            INSERT INTO {table_name} ({columns})
            VALUES ({placeholders})
        """

        cursor.execute(query, values)

    except Exception as e:
        print(f"Error inserting data into {table_name}: {e}")
        traceback.print_exc()
        print(f"Item: {data_item}")

def cleanup_old_tasks():
    """Remove old completed tasks from memory"""
    import threading
    import time
    
    def cleanup_worker():
        while True:
            try:
                current_time = time.time()
                # Remove tasks older than 1 hour
                cutoff_time = current_time - 3600  # 1 hour
                
                # Clean up task_progress
                tasks_to_remove = []
                for task_id, progress in task_progress.items():
                    if progress.get('progress', 0) >= 100 or progress.get('status') == 'error':
                        # Check if task is old enough to remove
                        if 'timestamp' not in progress:
                            progress['timestamp'] = current_time
                        elif current_time - progress['timestamp'] > 300:  # 5 minutes after completion
                            tasks_to_remove.append(task_id)
                
                for task_id in tasks_to_remove:
                    app.logger.info(f"[{task_id}] Task progress dibersihkan dari memory")
                    task_progress.pop(task_id, None)
                    task_results.pop(task_id, None)
                
                time.sleep(60)  # Run cleanup every minute
            except Exception as e:
                conn.rollback()  # Patch: rollback on error
                app.logger.error(f"Error in cleanup worker: {e}")
                time.sleep(60)
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()

# Initialize cleanup when the module loads
cleanup_old_tasks()

def process_uploaded_files(task_id, files, uploaded_files, user_info, uploaded_at):
    global uploaded_data
    global uploaded_data_2
    global uploaded_data_3
    global uploaded_data_2
    global uploaded_data_3
    global uploaded_data_4
    global uploaded_data_5
    global uploaded_data_6
    global uploaded_data_7
    global uploaded_data_8
    global uploaded_data_9
    global uploaded_data_10
    global uploaded_data_11
    
    global flag

    global active_facility_1
    global active_facility_2
    global active_facility_3
    global active_facility_4
    global active_facility_5

    global closed_facility_1
    global closed_facility_2
    global closed_facility_3
    global closed_facility_4
    global closed_facility_5
    
    uploaded_data_2 = None
    uploaded_data_3 = None
    uploaded_data_2 = None
    uploaded_data_3 = None
    uploaded_data_4 = None
    uploaded_data_5 = None
    uploaded_data_6 = None
    uploaded_data_7 = None
    uploaded_data_8 = None
    uploaded_data_9 = None
    uploaded_data_10 = None
    uploaded_data_11 = None
    flag = ''

    table_data = None
    table_data_2 = None
    table_data_3 = None
    table_data_4 = None
    table_data_5 = None
    table_data_6 = None
    table_data_7 = None
    table_data_8 = None
    table_data_9 = None
    table_data_10 = None
    table_data_11 = None

    table_data_af_1 = None
    table_data_af_2 = None
    table_data_af_3 = None
    table_data_af_4 = None
    table_data_af_5 = None

    table_data_cf_1 = None
    table_data_cf_2 = None
    table_data_cf_3 = None
    table_data_cf_4 = None
    table_data_cf_5 = None
    
    list_table_data = []
    conn = None

    json_header = None
    json_individual = None
    json_perusahaan = None
    json_paramPencarian = None
    json_dpdebitur = None
    json_kPengurusPemilik = None
    json_rFasilitas = None
    json_fKreditPembiayan = None
    json_fSuratBerharga = None
    json_fLC = None
    json_fGaransi = None
    json_fFasilitasLain = None

    df_kPengurusPemilik = None
    df_temp = None
    data_temp = None
    df_expanded = None

    active_facility_1 = None
    active_facility_2 = None
    active_facility_3 = None
    active_facility_4 = None
    active_facility_5 = None

    closed_facility_1 = None
    closed_facility_2 = None
    closed_facility_3 = None
    closed_facility_4 = None
    closed_facility_5 = None
    
    columns_to_remove = ['agunan', 'penjamin']
    
    all_uploaded_data = []
    list_debitur = []
    list_uploaded_data_6 = []
    list_uploaded_data_7 = []
    list_uploaded_data_8 = []
    list_uploaded_data_9 = []
    list_uploaded_data_10 = []
    
    jenis_surat_berharga = [
        {
            "Jenis Surat Berharga": "Sertifikat Bank Indonesia (SBI)",
            "Kode": "F0401"
        },
        {
            "Jenis Surat Berharga": "Sertifikat Deposito Bank Indonesia (SDBI)",
            "Kode": "F0403"
        },
        {
            "Jenis Surat Berharga": "Surat Berharga Bank Indonesia (SBBI) dalam",
            "Kode": "F0404"
        },
        {
            "Jenis Surat Berharga": "Surat Perbendaharaan Negara (SPN)",
            "Kode": "F040501"
        },
        {
            "Jenis Surat Berharga": "Surat Perbendaharaan Negara Syariah",
            "Kode": "F040502"
        },
        {
            "Jenis Surat Berharga": "(SIMA)",
            "Kode": "F0406"
        },
        {
            "Jenis Surat Berharga": "Promes/Aksep",
            "Kode": "F0408"
        },
        {
            "Jenis Surat Berharga": "Wesel - Wesel Ekspor",
            "Kode": "F040901"
        },
        {
            "Jenis Surat Berharga": "(SKBDN)",
            "Kode": "F040902"
        },
        {
            "Jenis Surat Berharga": "Wesel - Lainnya",
            "Kode": "F040999"
        },
        {
            "Jenis Surat Berharga": "Surat Berharga Komersial",
            "Kode": "F0410"
        },
        {
            "Jenis Surat Berharga": "Medium Term Notes (MTN)",
            "Kode": "F041101"
        },
        {
            "Jenis Surat Berharga": "Medium Term Notes (MTN) Syariah",
            "Kode": "F041102"
        },
        {
            "Jenis Surat Berharga": "Floating Rate Notes (FRN)",
            "Kode": "F0412"
        },
        {
            "Jenis Surat Berharga": "Credit Linked Notes",
            "Kode": "F0413"
        },
        {
            "Jenis Surat Berharga": "Reksadana",
            "Kode": "F041401"
        },
        {
            "Jenis Surat Berharga": "Reksadana Syariah",
            "Kode": "F041402"
        },
        {
            "Jenis Surat Berharga": "Reksadana Dana Pendapatan Tetap",
            "Kode": "F041403"
        },
        {
            "Jenis Surat Berharga": "Obligasi Dalam rangka program rekapitalisasi",
            "Kode": "F04150101"
        },
        {
            "Jenis Surat Berharga": "Obligasi Negara (ON)",
            "Kode": "F04150102"
        },
        {
            "Jenis Surat Berharga": "Obligasi Ritel Indonesia (ORI)",
            "Kode": "F04150103"
        },
        {
            "Jenis Surat Berharga": "Obligasi Korporasi - Subordinasi",
            "Kode": "F0415010501"
        },
        {
            "Jenis Surat Berharga": "Obligasi Korporasi - Non Subordinasi",
            "Kode": "F0415010602"
        },
        {
            "Jenis Surat Berharga": "Obligasi Lainnya",
            "Kode": "F04150199"
        },
        {
            "Jenis Surat Berharga": "Sukuk Bank Indonesia",
            "Kode": "F04150201"
        },
        {
            "Jenis Surat Berharga": "Sukuk Negara",
            "Kode": "F04150203"
        },
        {
            "Jenis Surat Berharga": "Sukuk Ritel",
            "Kode": "F04150204"
        },
        {
            "Jenis Surat Berharga": "Tjarah Fixed Rate",
            "Kode": "F04150205"
        },
        {
            "Jenis Surat Berharga": "Sukuk Korporasi - Subordinasi",
            "Kode": "F0415020601"
        },
        {
            "Jenis Surat Berharga": "Sukuk Korporasi - Non Subordinasi",
            "Kode": "F0415020602"
        },
        {
            "Jenis Surat Berharga": "Project Based Sukuk (PBS)",
            "Kode": "F04150207"
        },
        {
            "Jenis Surat Berharga": "Sukuk Valas Bank Indonesia (SUVBI)",
            "Kode": "F04150208"
        },
        {
            "Jenis Surat Berharga": "Sukuk Lainnya",
            "Kode": "F04150299"
        },
        {
            "Jenis Surat Berharga": "Dana Investasi Real Estate (DIRE)",
            "Kode": "F0416"
        },
        {
            "Jenis Surat Berharga": "Efek Beragun Aset",
            "Kode": "F041701"
        },
        {
            "Jenis Surat Berharga": "Efek Beragun Aset Syariah",
            "Kode": "F041702"
        },
        {
            "Jenis Surat Berharga": "Sekuritas Rupiah Bank Indonesia (SRBI)",
            "Kode": "F0422"
        },
        {
            "Jenis Surat Berharga": "Sekuritas Valas Bank Indonesia (SVBI)",
            "Kode": "F0423"
        },
        {
            "Jenis Surat Berharga": "Surat Berharga Lainnya",
            "Kode": "F0499"
        }
    ]

    username = user_info['username']
    nama_file = user_info['nama_file']
    current_datetime = datetime.now()
    total_files = len(files)
    
    identitas = None
    session_identitas = None
    
    npwp = None
    session_npwp = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        conn.autocommit = False
        
        for idx, uploaded_file in enumerate(uploaded_files, start=1):
            progress = 10 + int(70 * (idx / total_files))
            if task_id in task_progress:
                task_progress[task_id]['progress'] = progress
            
            filename = uploaded_file.filename
            if not filename.lower().endswith('.txt'):
                # Set error status dan stop processing
                task_progress[task_id]['status'] = 'error'
                return {
                    "error": True,
                    "error_type": "validation_error",
                    "message": f"File {filename} must have a .txt extension",
                    "redirect_url": "/upload-big-size"
                }
                
            if uploaded_file.mimetype != 'text/plain':
                # Set error status dan stop processing
                task_progress[task_id]['status'] = 'error'
                return {
                    "error": True,
                    "error_type": "validation_error", 
                    "message": f"File {filename} must be a plain text (.txt) file",
                    "redirect_url": "/upload-big-size"
                }
            
            if uploaded_file:
                try:
                    encodings = ['utf-8', 'utf-16', 'latin-1', 'ascii']
                    content = None
                    file_content = uploaded_file.stream.read()
                    
                    for encoding in encodings:
                        try:
                            uncleaned_content = file_content.decode(encoding, errors='ignore').strip()
                            content = re.sub(r'[^\x20-\x7E\t\r\n]', '', uncleaned_content)
                            break  # Jika berhasil, keluar dari loop
                        except (UnicodeDecodeError, LookupError):
                            continue  # Jika gagal, coba encoding berikutnya
                    
                    if content is None or len(content) == 0:
                        task_progress[task_id]['status'] = 'error'
                        return {
                            "error": True,
                            "error_type": "validation_error",
                            "message": f"Could not decode file {filename} with supported encodings",
                            "redirect_url": "/upload-big-size"
                        }

                    # Parse JSON dari konten
                    try:
                        data = json.loads(content)
                    except json.JSONDecodeError as e:
                        # Set error status dan stop processing
                        task_progress[task_id]['status'] = 'error'
                        return {
                            "error": True,
                            "error_type": "validation_error",
                            "message": f"Invalid JSON file {filename}: {str(e)}",
                            "redirect_url": "/upload-big-size"
                        }
                    
                    bulan_dict = {
                        1: "Januari", 2: "Februari", 3: "Maret", 4: "April",
                        5: "Mei", 6: "Juni", 7: "Juli", 8: "Agustus",
                        9: "September", 10: "Oktober", 11: "November", 12: "Desember"
                    }
                    
                    json_header = data['header']
                    if 'perusahaan' in data and isinstance(data['perusahaan'], dict) and data['perusahaan'].get('posisiDataTerakhir'):
                        data_perusahaan = data['perusahaan']
                        posisiDataTerakhir = data_perusahaan['posisiDataTerakhir']
                        json_paramPencarian = data_perusahaan.get('parameterPencarian', {})
                        npwp = json_paramPencarian.get('npwp', '')
                        print(f"Get NPWP: {npwp}")
                        
                        # Validasi NPWP untuk sesi upload
                        if session_npwp is None:
                            # File pertama - simpan NPWP sebagai referensi
                            print(f"Before NPWP: {session_npwp} - NPWP: {npwp}")
                            session_npwp = npwp
                            print(f"After NPWP: {session_npwp} - NPWP: {npwp}")
                        elif npwp != session_npwp:
                            return {
                                "error": True,
                                "error_type": "validation_error",
                                "message": f"File yang diupload tidak konsisten. File pertama: {session_npwp}, File ke-{idx}: {npwp}. Pastikan semua file dalam satu sesi upload memiliki NPWP yang sama.",
                                "redirect_url": "/upload-big-size"
                            }
                    elif 'individual' in data and isinstance(data['individual'], dict) and data['individual'].get('posisiDataTerakhir'):
                        data_individual = data['individual']
                        posisiDataTerakhir = data_individual['posisiDataTerakhir']
                        json_paramPencarian = data_individual.get('parameterPencarian', {})
                        identitas = json_paramPencarian.get('noIdentitas', '')
                        
                        # Validasi identitas untuk sesi upload
                        if session_identitas is None:
                            # File pertama - simpan identitas sebagai referensi
                            session_identitas = identitas
                        else:
                            # File kedua dan seterusnya - bandingkan dengan identitas file pertama
                            if identitas != session_identitas:
                                return {
                                    "error": True,
                                    "error_type": "validation_error",
                                    "message": f"File yang diupload tidak konsisten. File pertama: {session_identitas}, File ke-{idx}: {identitas}. Pastikan semua file dalam satu sesi upload memiliki Nomor Identitas yang sama.",
                                    "redirect_url": "/upload-big-size"
                                }
                                
                    date_obj = datetime.strptime(posisiDataTerakhir, "%Y%m")
                    json_posisiDataTerakhir = f"{bulan_dict[date_obj.month]} {date_obj.year}"
                    
                    if json_header:
                        try:
                            # Buat salinan tanpa key yang tidak dibutuhkan
                            filtered_item = {k: v for k, v in json_header.items() if k not in columns_to_remove}

                            # Siapkan nama kolom tambahan
                            base_columns = ['periodeData', 'username', 'namaFileUpload', 'uploadDate']
                            base_values = [json_posisiDataTerakhir, username, nama_file, current_datetime]

                            # Gabungkan kolom dan nilai tambahan dengan hasil filter
                            all_columns = base_columns + list(filtered_item.keys())
                            all_values = tuple(base_values + list(filtered_item.values()))

                            # Buat string kolom dan placeholders
                            columns = ', '.join(all_columns)
                            placeholders = ', '.join(['?'] * len(all_columns))

                            # Query insert akhir
                            query = f"""
                                INSERT INTO slik_header ({columns})
                                VALUES ({placeholders})
                            """

                            cur.execute(query, all_values)

                        except Exception as e:
                            conn.rollback()  # Patch: rollback on error
                            print(f"Error inserting data: {e}")
                            traceback.print_exc()
                            print(f"Item: {json_header}")
                            
                    uploaded_data = pd.DataFrame(json_header, index=[0])
                    table_data = uploaded_data.to_html(classes="table table-striped", index=False)
                    
                    if 'individual' in data:
                        
                        json_individual = data['individual']
                        json_paramPencarian = json_individual.get('parameterPencarian', {})
                        json_dpdebitur = json_individual.get('dataPokokDebitur', [])
                        json_rFasilitas = json_individual.get('ringkasanFasilitas', {})
                        fasilitas = json_individual.get('fasilitas', {})
                        json_fKreditPembiayan = fasilitas.get('kreditPembiayan', [])
                        json_fLC = fasilitas.get('lc', [])
                        json_fGaransi = fasilitas.get('garansiYgDiberikan', [])
                        json_fFasilitasLain = fasilitas.get('fasilitasLain', [])
                        nomor_laporan = json_individual.get('nomorLaporan')

                        # Hapus key yang ada saja
                        for key in ['dataPokokDebitur', 'parameterPencarian', 'ringkasanFasilitas', 'fasilitas']:
                            json_individual.pop(key, None)

                        uploaded_data_2 = pd.DataFrame(json_individual, index=[0]).fillna('')
                        uploaded_data_3 = pd.DataFrame(json_paramPencarian, index=[0]).fillna('')
                        uploaded_data_4 = pd.DataFrame(json_dpdebitur).fillna('')
                        uploaded_data_5 = pd.DataFrame(json_rFasilitas, index=[0]).fillna('')
                        
                        extra = {
                            'periodeData': json_posisiDataTerakhir,
                            'username': user_info['username'],
                            'namaFileUpload': user_info['nama_file'],
                            'uploadDate': current_datetime
                        }
                        
                        # Insert data ke database dengan pengecekan yang konsisten
                        if json_individual:
                            try:
                                insert_data(cur, "slik_perusahaan", {
                                    "nomorLaporan": json_individual.get("nomorLaporan"),
                                    "posisiDataTerakhir": json_individual.get("posisiDataTerakhir"),
                                    "tanggalPermintaan": json_individual.get("tanggalPermintaan")
                                }, extra_columns=extra)
                            except Exception as e:
                                conn.rollback()  # Patch: rollback on error
                                return {"error": f"Error processing file: {e}"}

                        if json_paramPencarian:
                            insert_data(cur, "slik_parameter_pencarian", json_paramPencarian, columns_to_remove, extra_columns=extra)

                        if json_dpdebitur:
                            for item in json_dpdebitur:
                                insert_data(cur, "slik_data_pokok_debitur", item, columns_to_remove, extra_columns=extra)

                        if json_rFasilitas:
                            insert_data(cur, "slik_ringkasan_fasilitas", json_rFasilitas, columns_to_remove, extra_columns=extra)
                        
                        if len(uploaded_files) > 1:
                        # table_data_6 = uploaded_data_6.to_html(classes="table table-striped", index=False)
                            all_uploaded_data.append(uploaded_data_2)
                            all_uploaded_data.append(uploaded_data_3)
                            all_uploaded_data.append(uploaded_data_4)
                            all_uploaded_data.append(uploaded_data_5)
                            # all_uploaded_data.append(uploaded_data_6)
                            
                            for data in all_uploaded_data:
                                table_html = data.to_html(classes="table table-striped", index=False).strip()
                                list_table_data.append(table_html)
                                
                        else:
                            table_data_2 = uploaded_data_2.to_html(classes="table table-striped", index=False)
                            table_data_3 = uploaded_data_3.to_html(classes="table table-striped", index=False)
                            table_data_4 = uploaded_data_4.to_html(classes="table table-striped", index=False)
                            table_data_5 = uploaded_data_5.to_html(classes="table table-striped", index=False)
                        
                        # Fasilitas Kredit Pembiayaan
                        if json_fKreditPembiayan:
                            for item in json_fKreditPembiayan:
                                insert_data(cur, "slik_fasilitas_kredit_pembiayaan", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_6 = pd.DataFrame(json_fKreditPembiayan)
                            uploaded_data_6.drop(columns=[col for col in columns_to_remove if col in uploaded_data_6.columns], inplace=True)
                            if len(uploaded_data_6) > 0:
                                uploaded_data_6 = uploaded_data_6.assign(**{'urutanFile': idx})
                            list_uploaded_data_6.append(uploaded_data_6)

                        # Fasilitas LC
                        if json_fLC:
                            for item in json_fLC:
                                insert_data(cur, "slik_fasilitas_lc", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_7 = pd.DataFrame(json_fLC)
                            uploaded_data_7.drop(columns=[col for col in columns_to_remove if col in uploaded_data_7.columns], inplace=True)
                            if len(uploaded_data_7) > 0:
                                uploaded_data_7 = uploaded_data_7.assign(**{'urutanFile': idx})
                            list_uploaded_data_7.append(uploaded_data_7)

                        # Fasilitas Garansi
                        if json_fGaransi:
                            for item in json_fGaransi:
                                insert_data(cur, "slik_fasilitas_garansi", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_8 = pd.DataFrame(json_fGaransi)
                            uploaded_data_8.drop(columns=[col for col in columns_to_remove if col in uploaded_data_8.columns], inplace=True)
                            if len(uploaded_data_8) > 0:
                                uploaded_data_8 = uploaded_data_8.assign(**{'urutanFile': idx})
                            list_uploaded_data_8.append(uploaded_data_8)

                        # Fasilitas Lainnya
                        if json_fFasilitasLain:
                            for item in json_fFasilitasLain:
                                insert_data(cur, "slik_fasilitas_lainnya", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_9 = pd.DataFrame(json_fFasilitasLain)
                            uploaded_data_9.drop(columns=[col for col in columns_to_remove if col in uploaded_data_9.columns], inplace=True)
                            if len(uploaded_data_9) > 0:
                                uploaded_data_9 = uploaded_data_9.assign(**{'urutanFile': idx})
                            list_uploaded_data_9.append(uploaded_data_9)
                            
                        # Set session data availability
                        if has_request_context():
                            session['data_available'] = True

                    elif 'perusahaan' in data:
                        
                        json_perusahaan = data['perusahaan']
                        json_paramPencarian = json_perusahaan.get('parameterPencarian', {})
                        json_dpdebitur = json_perusahaan.get('dataPokokDebitur', [])
                        json_rFasilitas = json_perusahaan.get('ringkasanFasilitas', {})
                        fasilitas = json_perusahaan.get('fasilitas', {})
                        
                        json_fKreditPembiayan = fasilitas.get('kreditPembiayan', [])
                        json_fSuratBerharga = fasilitas.get('suratBerharga', [])
                        json_fLC = fasilitas.get('lc', [])
                        json_fGaransi = fasilitas.get('garansiYgDiberikan', [])
                        json_fFasilitasLain = fasilitas.get('fasilitasLain', [])
                        json_kPengurusPemilik = json_perusahaan.get('kelompokPengurusPemilik', None)
                        nomor_laporan = json_perusahaan.get('nomorLaporan')

                        # Hapus key yang ada saja
                        for key in ['dataPokokDebitur', 'parameterPencarian', 'ringkasanFasilitas', 'fasilitas', 'kelompokPengurusPemilik']:
                            json_perusahaan.pop(key, None)
                        
                        uploaded_data_2 = pd.DataFrame(json_perusahaan, index=[0]).fillna('')
                        uploaded_data_3 = pd.DataFrame(json_paramPencarian, index=[0]).fillna('')
                        uploaded_data_4 = pd.DataFrame(json_dpdebitur).fillna('')
                        uploaded_data_5 = pd.DataFrame(json_rFasilitas, index=[0]).fillna('')
                        
                        extra = {
                            'periodeData': json_posisiDataTerakhir,
                            'username': user_info['username'],
                            'namaFileUpload': user_info['nama_file'],
                            'uploadDate': current_datetime
                        }
                        
                        if json_perusahaan:
                            insert_data(cur, "slik_perusahaan", {
                                "nomorLaporan": json_perusahaan.get("nomorLaporan"),
                                "posisiDataTerakhir": json_perusahaan.get("posisiDataTerakhir"),
                                "tanggalPermintaan": json_perusahaan.get("tanggalPermintaan")
                            }, extra_columns=extra)

                        if json_paramPencarian:
                            insert_data(cur, "slik_parameter_pencarian", json_paramPencarian, columns_to_remove, extra_columns=extra)

                        if json_dpdebitur:
                            for item in json_dpdebitur:
                                insert_data(cur, "slik_data_pokok_debitur", item, columns_to_remove, extra_columns=extra)

                        if json_kPengurusPemilik:
                            for kelompok in json_kPengurusPemilik:
                                for pengurus in kelompok["pengurusPemilik"]:
                                    full_item = {
                                        "kodeLJK": kelompok["kodeLJK"],
                                        "namaLJK": kelompok["namaLJK"],
                                        **pengurus
                                    }
                                    insert_data(cur, "slik_kelompok_pengurus_pemilik", full_item, columns_to_remove, extra_columns=extra)

                        if json_rFasilitas:
                            insert_data(cur, "slik_ringkasan_fasilitas", json_rFasilitas, columns_to_remove, extra_columns=extra)
                            
                        if len(uploaded_files) > 1:
                            all_uploaded_data.append(uploaded_data_2)
                            all_uploaded_data.append(uploaded_data_3)
                            all_uploaded_data.append(uploaded_data_4)
                            all_uploaded_data.append(uploaded_data_5)
                            
                            for data in all_uploaded_data:
                                table_html = data.to_html(classes="table table-striped", index=False).strip()
                                list_table_data.append(table_html)
                        else:
                            table_data_2 = uploaded_data_2.to_html(classes="table table-striped", index=False)
                            table_data_3 = uploaded_data_3.to_html(classes="table table-striped", index=False)
                            table_data_4 = uploaded_data_4.to_html(classes="table table-striped", index=False)
                            table_data_5 = uploaded_data_5.to_html(classes="table table-striped", index=False)
                        
                        if json_fKreditPembiayan:
                            for item in json_fKreditPembiayan:
                                insert_data(cur, "slik_fasilitas_kredit_pembiayaan", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_6 = pd.DataFrame(json_fKreditPembiayan)
                            uploaded_data_6.drop(columns=[col for col in columns_to_remove if col in uploaded_data_6.columns], inplace=True)
                            if len(uploaded_data_6) > 0:
                                uploaded_data_6 = uploaded_data_6.assign(**{'urutanFile': idx})
                            list_uploaded_data_6.append(uploaded_data_6)

                        # Fasilitas LC
                        if json_fLC:
                            for item in json_fLC:
                                insert_data(cur, "slik_fasilitas_lc", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_7 = pd.DataFrame(json_fLC)
                            uploaded_data_7.drop(columns=[col for col in columns_to_remove if col in uploaded_data_7.columns], inplace=True)
                            if len(uploaded_data_7) > 0:
                                uploaded_data_7 = uploaded_data_7.assign(**{'urutanFile': idx})
                            list_uploaded_data_7.append(uploaded_data_7)

                        # Fasilitas Garansi
                        if json_fGaransi:
                            for item in json_fGaransi:
                                insert_data(cur, "slik_fasilitas_garansi", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_8 = pd.DataFrame(json_fGaransi)
                            uploaded_data_8.drop(columns=[col for col in columns_to_remove if col in uploaded_data_8.columns], inplace=True)
                            if len(uploaded_data_8) > 0:
                                uploaded_data_8 = uploaded_data_8.assign(**{'urutanFile': idx})
                            list_uploaded_data_8.append(uploaded_data_8)

                        # Fasilitas Lainnya
                        if json_fFasilitasLain:
                            for item in json_fFasilitasLain:
                                insert_data(cur, "slik_fasilitas_lainnya", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_9 = pd.DataFrame(json_fFasilitasLain)
                            uploaded_data_9.drop(columns=[col for col in columns_to_remove if col in uploaded_data_9.columns], inplace=True)
                            if len(uploaded_data_9) > 0:
                                uploaded_data_9 = uploaded_data_9.assign(**{'urutanFile': idx})
                            list_uploaded_data_9.append(uploaded_data_9)

                        # Surat Berharga
                        if json_fSuratBerharga:
                            for item in json_fSuratBerharga:
                                insert_data(cur, "slik_fasilitas_surat_berharga", item, columns_to_remove, extra_columns=extra)

                            uploaded_data_10 = pd.DataFrame(json_fSuratBerharga)
                            uploaded_data_10.drop(columns=[col for col in columns_to_remove if col in uploaded_data_10.columns], inplace=True)
                            if len(uploaded_data_10) > 0:
                                uploaded_data_10 = uploaded_data_10.assign(**{'urutanFile': idx})
                            list_uploaded_data_10.append(uploaded_data_10)      
                                            
                        if json_kPengurusPemilik:
                            df_kPengurusPemilik = pd.DataFrame(json_kPengurusPemilik) 
                            data_temp = {'kodeLJK': ['1', '2', '3'], 'namaLJK': ['A', 'B', 'C'], 'pengurusPemilik': ['X', 'Y', 'Z']}
                            df_temp = pd.DataFrame(data_temp)
                            df_expanded = df_temp.head(0)

                            for row in df_kPengurusPemilik.itertuples(index=False):
                                for x in row.pengurusPemilik:
                                    df_expanded.loc[len(df_expanded)] = [row.kodeLJK, row.namaLJK, x]
                        
                            df_expanded = df_expanded.join(pd.json_normalize(df_expanded.pop('pengurusPemilik')))

                            uploaded_data_11 = df_expanded
                            table_data_11 = uploaded_data_11.to_html(classes="table table-striped", index=False)
                    if has_request_context():
                        session['data_available'] = True
                    
                except Exception as e:
                    conn.rollback()  # Patch: rollback on error
                    # task_progress[task_id]['status'] = 'error'
                    app.logger.error(f"[{task_id}] Error processing file {filename}: {str(e)}")
                    return {
                        "error": True,
                        "error_type": "system_error",
                        "message": f"Error processing file {filename}: {str(e)}",
                        "redirect_url": "/upload-big-size"
                    }
            else:
                # task_progress[task_id]['status'] = 'error'
                return {
                    "error": True,
                    "error_type": "validation_error",
                    "message": "Please upload a valid Text file",
                    "redirect_url": "/upload-big-size"
                }
        
        # Process the combined dataframes
        table_data_6 = (
            "\n".join([df.to_html(classes="table table-striped", index=False) for df in list_uploaded_data_6])
            if list_uploaded_data_6
            else "No data available."
        )
        
        table_data_7 = (
            "\n".join([df.to_html(classes="table table-striped", index=False) for df in list_uploaded_data_7])
            if list_uploaded_data_7
            else "No data available."
        )
        
        table_data_8 = (
            "\n".join([df.to_html(classes="table table-striped", index=False) for df in list_uploaded_data_8])
            if list_uploaded_data_8
            else "No data available."
        )
        
        table_data_9 = (
            "\n".join([df.to_html(classes="table table-striped", index=False) for df in list_uploaded_data_9])
            if list_uploaded_data_9
            else "No data available."
        )
        
        table_data_10 = (
            "\n".join([df.to_html(classes="table table-striped", index=False) for df in list_uploaded_data_10])
            if list_uploaded_data_10
            else "No data available."
        )
        
        task_progress[task_id]['progress'] = 90
        
        if len(list_uploaded_data_6) > 0:
            missing_ljk = [i for i, df in enumerate(list_uploaded_data_6) if 'ljk' not in df.columns]
            if not missing_ljk:
                try:
                    uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                    combined_data_6 = pd.concat(list_uploaded_data_6, ignore_index=True)
                    merged_fKP = combined_data_6.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                    print(f"Jumlah data setelah merge: {len(merged_fKP)}")
                
                    # ACTIVE FACILITY (Kondisi == '00')
                    active_fKP = merged_fKP[merged_fKP['kondisi'] == '00']
                    print(f"Jumlah data fasilitas aktif: {len(active_fKP)}")
                
                    if not active_fKP.empty:
                        # Daftar kolom yang dibutuhkan
                        columns = [
                            'namaDebitur', 'npwp', 'alamat', 'ljkKet',
                            'jenisKreditPembiayaanKet', 'jenisPenggunaanKet', 'plafon',
                            'bakiDebet', 'tunggakanPokok', 'tunggakanBunga', 'denda',
                            'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24', 'urutanFile'
                        ]

                        # Tambahkan kolom opsional jika tersedia
                        if 'tglAktaPendirian' in active_fKP.columns:
                            columns.insert(2, 'tglAktaPendirian')
                        elif 'tanggalLahir' in active_fKP.columns:
                            base_columns.insert(2, 'tanggalLahir')
                            
                        if 'valutaKode' in active_fKP.columns:
                            columns.insert(12, 'valutaKode')

                        # Filter kolom yang ada
                        available_columns = [col for col in columns if col in active_fKP.columns]
                        active_facility_1 = active_fKP[available_columns].copy()
                        
                        # Tambahkan kolom metadata
                        active_facility_1['periodeData'] = json_posisiDataTerakhir
                        active_facility_1['username'] = username
                        active_facility_1['namaFileUpload'] = nama_file
                        active_facility_1['uploadDate'] = current_datetime
                        
                        # Rename dict untuk tampilan HTML
                        rename_dict = {
                            'namaDebitur': 'Nama Debitur/Calon Debitur',
                            'npwp': 'Nomor Identitas',
                            'alamat': 'Alamat',
                            'ljkKet': 'Kreditur/Pelapor',
                            'jenisKreditPembiayaanKet': 'Jenis Kredit/Pembiayaan',
                            'jenisPenggunaanKet': 'Jenis Penggunaan',
                            'plafon': 'Plafon',
                            'bakiDebet': 'Oustanding/Baki Debet',
                            'tunggakanPokok': 'Tunggakan Pokok',
                            'tunggakanBunga': 'Tunggakan Bunga',
                            'denda': 'Denda',
                            'jumlahHariTunggakan': 'Hari Keterlambatan',
                            'kualitas': 'Kode Kolektibilitas Saat ini',
                            'kualitasKet': 'Kolektibilitas Saat ini',
                            'tahunBulan24': 'Periode Pelaporan Terakhir',
                            'urutanFile': 'File ke'
                        }
                        if 'tglAktaPendirian' in active_fKP.columns:
                            rename_dict['tglAktaPendirian'] = 'Tanggal Pendirian'
                        elif 'tanggalLahir' in active_fKP.columns:
                            rename_dict['tanggalLahir'] = 'Tanggal Lahir'

                        
                        if 'valutaKode' in active_fKP.columns:
                            rename_dict['valutaKode'] = 'Valuta'
                        
                        # === Persiapkan data summary ===
                        summary_columns = [
                            'periodeData', 'username', 'namaFileUpload', 'uploadDate',
                            'namaDebitur', 'nomorLaporan', 'nomorIdentitas', 'kreditur',
                            'jenisPembiayaan', 'kodeKolektibilitas', 'kolektibilitas'
                        ]

                        # Buat dictionary untuk pemetaan kolom
                        summary_map = {
                            'periodeData': 'periodeData', 
                            'username': 'username',
                            'namaFileUpload': 'namaFileUpload', 
                            'uploadDate': 'uploadDate',
                            'namaDebitur': 'namaDebitur', 
                            'nomorLaporan': None,
                            'nomorIdentitas': 'npwp', 
                            'kreditur': 'ljkKet',
                            'jenisPembiayaan': 'jenisKreditPembiayaanKet', 
                            'kodeKolektibilitas': 'kualitas',
                            'kolektibilitas': 'kualitasKet'
                        }
                        
                        # Buat DataFrame summary baru
                        summary_data = pd.DataFrame()
                        for target_col, source_col in summary_map.items():
                            if source_col is None:
                                if target_col == 'nomorLaporan':
                                    summary_data[target_col] = nomor_laporan
                            elif source_col in active_facility_1.columns:
                                summary_data[target_col] = active_facility_1[source_col]
                            else:
                                summary_data[target_col] = None
                        
                        # Konversi NaN ke None untuk semua DataFrame
                        summary_data = summary_data.replace({np.nan: None})
                        active_facility_1 = active_facility_1.replace({np.nan: None})
                        
                        # Insert data summary
                        try:
                            summary_columns_sql = ', '.join(summary_columns)
                            summary_placeholders = ', '.join(['?'] * len(summary_columns))
                            summary_query = f"""
                                INSERT INTO slik_summary_fasilitas_aktif ({summary_columns_sql})
                                VALUES ({summary_placeholders})
                            """
                            
                            summary_values = list(summary_data.itertuples(index=False, name=None))
                            if summary_values:
                                print(f"Inserting {len(summary_values)} records into slik_summary_fasilitas_aktif")
                                cur.executemany(summary_query, summary_values)
                                print("Data summary berhasil di-insert!")
                            else:
                                print("Tidak ada data summary untuk di-insert!")
                        except Exception as e:
        
                            conn.rollback()
                            print(f"Error saat insert data summary: {str(e)}")
                        
                        # Insert ke tabel fasilitas aktif
                        try:
                            columns_af = ', '.join(active_facility_1.columns)
                            placeholders = ', '.join(['?'] * len(active_facility_1.columns))
                            query = f"""
                                INSERT INTO slik_fasilitas_aktif_kredit_pembiayaan ({columns_af})
                                VALUES ({placeholders})
                            """
                            
                            data = list(active_facility_1.itertuples(index=False, name=None))
                            if data:
                                cur.executemany(query, data)
                                print("Data aktif berhasil di-insert!")
                            else:
                                print("Data fasilitas aktif kosong!")
                        except Exception as e:
        
                            conn.rollback()
                            print(f"Error saat insert data aktif: {str(e)}")

                        # Persiapkan data untuk tabel HTML
                        active_facility_display = active_facility_1.copy()
                        active_facility_display = active_facility_display.rename(columns=rename_dict)
                        active_facility_display.insert(1, 'Nomor Laporan', nomor_laporan)
                        active_facility_display = active_facility_display.reset_index(names='No')
                        active_facility_display['No'] = active_facility_display.index + 1
                        active_facility_display = active_facility_display.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                        table_data_af_1 = active_facility_display.to_html(classes="table table-striped", index=False)
                    else:
                        print("Tidak ada data fasilitas aktif (kondisi = '00')")
                        table_data_af_1 = "<p>Tidak ada data fasilitas aktif</p>"

                    # CLOSED FACILITY (Kondisi == '02')
                    closed_fKP = merged_fKP[merged_fKP['kondisi'] == '02']
                    columns_closed = [
                        'namaDebitur', 'npwp', 'alamat', 'ljkKet',
                        'jenisKreditPembiayaanKet', 'jenisPenggunaanKet', 'plafon',
                        'bakiDebet', 'tunggakanPokok', 'tunggakanBunga', 'denda',
                        'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24', 'urutanFile'
                    ]

                    if 'tglAktaPendirian' in closed_fKP.columns:
                        columns_closed.insert(2, 'tglAktaPendirian')
                    elif 'tanggalLahir' in closed_fKP.columns:    
                        columns_closed.insert(2, 'tanggalLahir')
                        
                    if 'valutaKode' in closed_fKP.columns:
                        columns_closed.insert(12, 'valutaKode')  # Fixed here - was using 'columns' instead of 'columns_closed'

                    closed_facility_1 = closed_fKP[columns_closed]
                    rename_dict_closed = {
                        'namaDebitur': 'Nama Debitur/Calon Debitur',
                        'npwp': 'Nomor Identitas',
                        'alamat': 'Alamat',
                        'ljkKet': 'Kreditur/Pelapor',
                        'jenisKreditPembiayaanKet': 'Jenis Kredit/Pembiayaan',
                        'jenisPenggunaanKet': 'Jenis Penggunaan',
                        'plafon': 'Plafon',
                        'bakiDebet': 'Oustanding/Baki Debet',
                        'tunggakanPokok': 'Tunggakan Pokok',
                        'tunggakanBunga': 'Tunggakan Bunga',
                        'denda': 'Denda',
                        'jumlahHariTunggakan': 'Hari Keterlambatan',
                        'kualitas': 'Kode Kolektibilitas Saat ini',
                        'kualitasKet': 'Kolektibilitas Saat ini',
                        'tahunBulan24': 'Periode Pelaporan Terakhir',
                        'urutanFile': 'File ke'
                    }

                    if 'tglAktaPendirian' in closed_fKP.columns:
                        rename_dict_closed['tglAktaPendirian'] = 'Tanggal Pendirian'
                    elif 'tanggalLahir' in closed_fKP.columns:
                        rename_dict_closed['tanggalLahir'] = 'Tanggal Lahir'
                        
                    if 'valutaKode' in closed_fKP.columns:
                        rename_dict_closed['valutaKode'] = 'Valuta'  # Fixed here - was using 'rename_dict' instead of 'rename_dict_closed'
                        
                    closed_facility_1['periodeData'] = json_posisiDataTerakhir
                    closed_facility_1['username'] = username
                    closed_facility_1['namaFileUpload'] = nama_file
                    closed_facility_1['uploadDate'] = current_datetime
                    
                    # Ambil nama kolom dari DataFrame
                    columns_cf = ', '.join(closed_facility_1.columns)  # Changed variable name to avoid conflict

                    # Placeholder SQL Server pakai '?'
                    placeholders = ', '.join(['?'] * len(closed_facility_1.columns))

                    # Buat query insert
                    query = f"""
                        INSERT INTO slik_fasilitas_lunas_kredit_pembiayaan ({columns_cf})
                        VALUES ({placeholders})
                    """
                    # Ubah DataFrame ke list of tuple tanpa index
                    data = list(closed_facility_1.itertuples(index=False, name=None))
                    
                    # Jalankan batch insert
                    if data:
                        cur.executemany(query, data)
                    else:
                        print("Data kosong!")
                    
                    closed_facility_1 = closed_facility_1.rename(columns=rename_dict_closed)
                    closed_facility_1.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)  # Added this line to match active_facility_1 treatment
                    closed_facility_1 = closed_facility_1.reset_index(names='No')
                    closed_facility_1['No'] = closed_facility_1.index + 1
                    closed_facility_1 = closed_facility_1.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                    table_data_cf_1 = closed_facility_1.to_html(classes="table table-striped", index=False)
                except Exception as e:
                    conn.rollback()  # Patch: rollback on error
                    table_data_af_1 = f"Error processing active facilities: {e}"
                    table_data_cf_1 = f"Error processing closed facilities: {e}"
        
        if len(list_uploaded_data_7) > 0:
            # Periksa apakah semua DataFrame dalam list memiliki kolom 'ljk'
            missing_ljk = [i for i, df in enumerate(list_uploaded_data_7) if 'ljk' not in df.columns]
            if not missing_ljk:
                try:
                    # Proses data umum
                    def process_data(df_filtered, table_name, summary_table=None):
                        # Kolom dasar yang dibutuhkan
                        base_columns = [
                            'namaDebitur', 'npwp', 'alamat',
                            'ljkKet', 'jenisLcKet', 'tujuanLcKet', 'plafon', 'nominalLc',
                            'tanggalWanPrestasi', 'kualitas', 'kualitasKet',
                            'tahunBulan24', 'urutanFile'
                        ]
                        
                        if 'tanggalLahir' in df_filtered.columns:
                            base_columns.insert(2, 'tanggalLahir')
                        elif 'tglAktaPendirian' in df_filtered.columns:
                            base_columns.insert(2, 'tglAktaPendirian')
                        
                        # Tambahkan kolom 'valuta' jika tersedia
                        if 'valuta' in df_filtered.columns:
                            base_columns.insert(9, 'valuta')
                        
                        # Siapkan DataFrame untuk disimpan ke database
                        result_df = df_filtered[base_columns].copy()
                        result_df['periodeData'] = json_posisiDataTerakhir
                        result_df['username'] = username
                        result_df['namaFileUpload'] = nama_file
                        result_df['uploadDate'] = current_datetime
                        
                        # Insert ke database
                        if not result_df.empty:
                            columns = ', '.join(result_df.columns)
                            placeholders = ', '.join(['?'] * len(result_df.columns))
                            query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
                            data = list(result_df.itertuples(index=False, name=None))
                            cur.executemany(query, data)
                        
                        # Tambahkan ke tabel summary jika diperlukan
                        if summary_table and not result_df.empty:
                            summary_data = result_df.copy()
                            summary_data['nomorLaporan'] = nomor_laporan
                            summary_data.rename(columns={
                                'namaDebitur': 'namaDebitur',
                                'npwp': 'nomorIdentitas',
                                'ljkKet': 'kreditur',
                                'jenisLcKet': 'jenisPembiayaan',
                                'kualitas': 'kodeKolektibilitas',
                                'kualitasKet': 'kolektibilitas'
                            }, inplace=True)
                            
                            summary_columns = [
                                'periodeData', 'username', 'namaFileUpload', 'uploadDate',
                                'namaDebitur', 'nomorLaporan', 'nomorIdentitas',
                                'kreditur', 'jenisPembiayaan', 'kodeKolektibilitas', 'kolektibilitas'
                            ]
                            
                            summary_df = summary_data[summary_columns]
                            summary_query = f"""
                                INSERT INTO {summary_table} ({', '.join(summary_columns)})
                                VALUES ({', '.join(['?'] * len(summary_columns))})
                            """
                            summary_tuples = list(summary_df.itertuples(index=False, name=None))
                            cur.executemany(summary_query, summary_tuples)
                        
                        # Format data untuk HTML display
                        column_rename_map = {
                            'namaDebitur': 'Nama Debitur/Calon Debitur',
                            'npwp': 'Nomor Identitas',
                            'tglAktaPendirian': 'Tanggal Lahir/Pendirian',
                            'alamat': 'Alamat',
                            'ljkKet': 'Kreditur/Pelapor',
                            'jenisLcKet': 'Jenis L/C',
                            'tujuanLcKet': 'Tujuan L/C',
                            'plafon': 'Plafon',
                            'nominalLc': 'Oustanding/Baki Debet',
                            'valuta': 'Valuta',
                            'tanggalWanPrestasi': 'Tanggal Wan prestasi',
                            'kualitas': 'Kode Kolektibilitas Saat ini',
                            'kualitasKet': 'Kolektibilitas Saat ini',
                            'tahunBulan24': 'Periode Pelaporan Terakhir',
                            'urutanFile': 'File ke'
                        }
                        
                        display_df = result_df.rename(columns=column_rename_map)
                        if summary_table:  # Hanya tambahkan nomor laporan jika ini adalah fasilitas aktif
                            display_df.insert(1, 'Nomor Laporan', nomor_laporan)
                        display_df.reset_index(drop=True, inplace=True)
                        display_df.insert(0, 'No', range(1, len(display_df) + 1))
                        display_df = display_df.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                        
                        return display_df.to_html(classes="table table-striped", index=False)
                    
                    # Deduplicate dan gabungkan data
                    uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                    combined_data_7 = pd.concat(list_uploaded_data_7, ignore_index=True)
                    merged_fLC = combined_data_7.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
                    
                    # Proses fasilitas aktif
                    active_fLC = merged_fLC[merged_fLC['kondisi'] == '00']
                    table_data_af_2 = process_data(
                        active_fLC, 
                        'slik_fasilitas_aktif_lc', 
                        'slik_summary_fasilitas_aktif'
                    )
                    
                    # Proses fasilitas lunas
                    closed_fLC = merged_fLC[merged_fLC['kondisi'] == '02']
                    table_data_cf_2 = process_data(
                        closed_fLC, 
                        'slik_fasilitas_lunas_lc'
                    )
                    
                except Exception as e:
                    conn.rollback()  # Patch: rollback on error
                    table_data_af_2 = f"Error processing active facilities: {e}"
                    table_data_cf_2 = f"Error processing closed facilities: {e}"
                    
        if len(list_uploaded_data_8) > 0:
            missing_ljk = [i for i, df in enumerate(list_uploaded_data_7) if 'ljk' not in df.columns]
            if not missing_ljk:
                try:
                    # Fungsi umum untuk memproses dan menyimpan data
                    def process_guarantee_data(df_filtered, table_name, is_active=False):
                        # Kolom dasar yang dibutuhkan
                        base_columns = [
                            'namaDebitur', 'npwp', 'alamat',
                            'ljkKet', 'jenisGaransiKet', 'tujuanGaransiKet', 'plafon',
                            'nominalBg', 'tanggalWanPrestasi', 'kualitas',
                            'kualitasKet', 'tahunBulan24', 'urutanFile'
                        ]
                        
                        if 'tanggalLahir' in df_filtered.columns:
                            base_columns.insert(2, 'tanggalLahir')
                        elif 'tglAktaPendirian' in df_filtered.columns:
                            base_columns.insert(2, 'tglAktaPendirian')
                        
                        # Tambahkan kolom valuta jika tersedia (dengan penanganan nama kolom yang berbeda)
                        valuta_column = 'kodeValuta' if 'kodeValuta' in df_filtered.columns else 'valutaKode'
                        if valuta_column in df_filtered.columns:
                            base_columns.insert(9, valuta_column)
                        
                        # Siapkan DataFrame untuk disimpan ke database
                        result_df = df_filtered[base_columns].copy()
                        result_df['periodeData'] = json_posisiDataTerakhir
                        result_df['username'] = username
                        result_df['namaFileUpload'] = nama_file
                        result_df['uploadDate'] = current_datetime
                        
                        # Insert ke database
                        if not result_df.empty:
                            columns = ', '.join(result_df.columns)
                            placeholders = ', '.join(['?'] * len(result_df.columns))
                            query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
                            data = list(result_df.itertuples(index=False, name=None))
                            cur.executemany(query, data)
                        else:
                            print("Data kosong!")
                        
                        # Jika aktif, tambahkan ke tabel summary
                        if is_active and not result_df.empty:
                            summary_data = result_df[[
                                'namaDebitur', 'npwp', 'ljkKet', 'jenisGaransiKet', 'kualitas', 'kualitasKet'
                            ]].copy()
                            
                            summary_data['periodeData'] = json_posisiDataTerakhir
                            summary_data['username'] = username
                            summary_data['namaFileUpload'] = nama_file
                            summary_data['uploadDate'] = current_datetime
                            summary_data['nomorLaporan'] = nomor_laporan
                            
                            summary_data = summary_data.rename(columns={
                                'namaDebitur': 'namaDebitur',
                                'npwp': 'nomorIdentitas',
                                'ljkKet': 'kreditur',
                                'jenisGaransiKet': 'jenisPembiayaan',
                                'kualitas': 'kodeKolektibilitas',
                                'kualitasKet': 'kolektibilitas'
                            })
                            
                            summary_columns = [
                                'periodeData', 'username', 'namaFileUpload', 'uploadDate',
                                'namaDebitur', 'nomorLaporan', 'nomorIdentitas',
                                'kreditur', 'jenisPembiayaan', 'kodeKolektibilitas', 'kolektibilitas'
                            ]
                            
                            summary_df = summary_data[summary_columns]
                            summary_query = f"""
                                INSERT INTO slik_summary_fasilitas_aktif ({', '.join(summary_columns)})
                                VALUES ({', '.join(['?'] * len(summary_columns))})
                            """
                            summary_tuples = list(summary_df.itertuples(index=False, name=None))
                            
                            if summary_tuples:
                                cur.executemany(summary_query, summary_tuples)
                        
                        # Format data untuk HTML display
                        column_rename_map = {
                            'namaDebitur': 'Nama Debitur/Calon Debitur',
                            'npwp': 'Nomor Identitas',
                            'tglAktaPendirian': 'Tanggal Lahir/Pendirian',
                            'alamat': 'Alamat',
                            'ljkKet': 'Kreditur/Pelapor',
                            'jenisGaransiKet': 'Jenis Garansi',
                            'tujuanGaransiKet': 'Tujuan Garansi',
                            'plafon': 'Plafon',
                            'nominalBg': 'Oustanding/Baki Debet',
                            'kodeValuta': 'Valuta',
                            'valutaKode': 'Valuta',
                            'tanggalWanPrestasi': 'Tanggal Wan Prestasi',
                            'kualitas': 'Kode Kolektibilitas Saat ini',
                            'kualitasKet': 'Kolektibilitas Saat ini',
                            'tahunBulan24': 'Periode Pelaporan Terakhir',
                            'urutanFile': 'File ke'
                        }
                        
                        display_df = result_df.rename(columns=column_rename_map)
                        display_df.reset_index(drop=True, inplace=True)
                        
                        # Tambahkan Nomor Laporan untuk fasilitas aktif
                        if is_active:
                            display_df.insert(1, 'Nomor Laporan', nomor_laporan)
                        
                        # Tambahkan nomor urut
                        display_df.insert(0, 'No', range(1, len(display_df) + 1))
                        
                        # Hapus kolom internal
                        display_df = display_df.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                        
                        return display_df.to_html(classes="table table-striped", index=False)
                    
                    # Persiapan data
                    uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                    combined_data_8 = pd.concat(list_uploaded_data_8, ignore_index=True)
                    merged_fGar = combined_data_8.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
                    
                    # Proses fasilitas aktif
                    active_fGar = merged_fGar[merged_fGar['kodeKondisi'] == '00']
                    table_data_af_3 = process_guarantee_data(
                        active_fGar, 
                        'slik_fasilitas_aktif_bank_garansi',
                        is_active=True
                    )
                    
                    # Proses fasilitas lunas
                    closed_fGar = merged_fGar[merged_fGar['kodeKondisi'] == '02']
                    table_data_cf_3 = process_guarantee_data(
                        closed_fGar, 
                        'slik_fasilitas_lunas_bank_garansi'
                    )
                    
                except Exception as e:
                    conn.rollback()  # Patch: rollback on error
                    table_data_af_3 = f"Error processing active facilities: {e}"
                    table_data_cf_3 = f"Error processing closed facilities: {e}"
                    
        if len(list_uploaded_data_9) > 0:
            missing_ljk = [i for i, df in enumerate(list_uploaded_data_9) if 'ljk' not in df.columns]
            print({
                "missing_ljk":len(missing_ljk),
                "list_uploaded_data_9":len(list_uploaded_data_9)
                })
            if not missing_ljk:
                try:
                    # Fungsi umum untuk memproses dan menyimpan data fasilitas lainnya
                    def process_other_facility(df_filtered, table_name, is_active=False):
                        # Kolom dasar yang dibutuhkan
                        base_columns = [
                            'namaDebitur', 'npwp', 'alamat',
                            'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR',
                            'jumlahHariTunggakan', 'kualitas',
                            'kualitasKet', 'tahunBulan24', 'urutanFile'
                        ]
                        
                        if 'tanggalLahir' in df_filtered.columns:
                            base_columns.insert(2, 'tanggalLahir')
                        elif 'tglAktaPendirian' in df_filtered.columns:
                            base_columns.insert(2, 'tglAktaPendirian')
                        
                        # Tambahkan kolom valuta jika tersedia
                        if 'kodeValuta' in df_filtered.columns:
                            base_columns.insert(7, 'kodeValuta')
                        
                        # Siapkan DataFrame untuk disimpan ke database
                        result_df = df_filtered[base_columns].copy()
                        
                        # Tambahkan kolom metadata
                        metadata_columns = {
                            'periodeData': json_posisiDataTerakhir,
                            'username': username,
                            'namaFileUpload': nama_file,
                            'uploadDate': current_datetime
                        }
                        
                        for col, val in metadata_columns.items():
                            result_df[col] = val
                        
                        # Insert ke database utama jika ada data
                        if not result_df.empty:
                            columns = ', '.join(result_df.columns)
                            placeholders = ', '.join(['?'] * len(result_df.columns))
                            query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
                            data = list(result_df.itertuples(index=False, name=None))
                            cur.executemany(query, data)
                        else:
                            print("Data kosong!")
                        
                        # Insert ke tabel summary jika fasilitas aktif
                        if is_active and not result_df.empty:
                            # Kolom yang dibutuhkan untuk summary
                            summary_base = [
                                'namaDebitur', 'npwp', 'ljkKet', 'jenisFasilitasKet', 'kualitas', 'kualitasKet'
                            ]
                            
                            summary_data = result_df[summary_base].copy()
                            
                            # Tambah metadata dan nomor laporan
                            for col, val in metadata_columns.items():
                                summary_data[col] = val
                            summary_data['nomorLaporan'] = nomor_laporan
                            
                            # Rename kolom sesuai struktur tabel summary
                            summary_mapping = {
                                'npwp': 'nomorIdentitas',
                                'ljkKet': 'kreditur',
                                'jenisFasilitasKet': 'jenisPembiayaan',
                                'kualitas': 'kodeKolektibilitas',
                                'kualitasKet': 'kolektibilitas'
                            }
                            summary_data = summary_data.rename(columns=summary_mapping)
                            
                            # Tentukan urutan kolom
                            summary_columns = [
                                'periodeData', 'username', 'namaFileUpload', 'uploadDate',
                                'namaDebitur', 'nomorLaporan', 'nomorIdentitas',
                                'kreditur', 'jenisPembiayaan', 'kodeKolektibilitas', 'kolektibilitas'
                            ]
                            
                            summary_df = summary_data[summary_columns]
                            
                            # Buat query insert
                            summary_query = f"""
                                INSERT INTO slik_summary_fasilitas_aktif ({', '.join(summary_columns)})
                                VALUES ({', '.join(['?'] * len(summary_columns))})
                            """
                            summary_tuples = list(summary_df.itertuples(index=False, name=None))
                            
                            if summary_tuples:
                                cur.executemany(summary_query, summary_tuples)
                        
                        # Format data untuk tampilan HTML
                        column_rename_map = {
                            'namaDebitur': 'Nama Debitur/Calon Debitur',
                            'npwp': 'Nomor Identitas',
                            'tglAktaPendirian': 'Tanggal Lahir/Pendirian',
                            'alamat': 'Alamat',
                            'ljkKet': 'Kreditur/Pelapor',
                            'jenisFasilitasKet': 'Jenis Fasilitas',
                            'nominalJumlahKwajibanIDR': 'Oustanding/Baki Debet',
                            'kodeValuta': 'Valuta',
                            'jumlahHariTunggakan': 'Hari Keterlambatan',
                            'kualitas': 'Kode Kolektibilitas Saat ini',
                            'kualitasKet': 'Kolektibilitas Saat ini',
                            'tahunBulan24': 'Periode Pelaporan Terakhir',
                            'urutanFile': 'File ke'
                        }
                        
                        display_df = result_df.rename(columns=column_rename_map)
                        display_df.reset_index(drop=True, inplace=True)
                        
                        # Tambahkan Nomor Laporan jika fasilitas aktif
                        if is_active:
                            display_df.insert(1, 'Nomor Laporan', nomor_laporan)
                        
                        # Tambahkan nomor urut
                        display_df.insert(0, 'No', range(1, len(display_df) + 1))
                        
                        # Hapus kolom metadata
                        display_df = display_df.drop(columns=list(metadata_columns.keys()), errors='ignore')
                        
                        return display_df.to_html(classes="table table-striped", index=False)
                    
                    # Persiapan data
                    uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                    combined_data_9 = pd.concat(list_uploaded_data_9, ignore_index=True)
                    merged_fLain = combined_data_9.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
                    
                    print(merged_fLain)
                    
                    # Proses fasilitas aktif
                    active_fLain = merged_fLain[merged_fLain['kodeKondisi'] == '00']
                    table_data_af_4 = process_other_facility(
                        active_fLain, 
                        'slik_fasilitas_aktif_lainnya',
                        is_active=True
                    )
                    
                    # Proses fasilitas lunas
                    closed_fLain = merged_fLain[merged_fLain['kodeKondisi'] == '02']
                    table_data_cf_4 = process_other_facility(
                        closed_fLain, 
                        'slik_fasilitas_lunas_lainnya'
                    )
                    
                except Exception as e:
                    conn.rollback()  # Patch: rollback on error
                    table_data_af_4 = f"Error processing active facilities: {e}"
                    table_data_cf_4 = f"Error processing closed facilities: {e}"
                
        if len(list_uploaded_data_10) > 0:
            missing_ljk = [i for i, df in enumerate(list_uploaded_data_7) if 'ljk' not in df.columns]
            if not missing_ljk:
                try:
                    # 1. Data preparation
                    uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                    combined_data_10 = pd.concat(list_uploaded_data_10, ignore_index=True)
                    merged_fSB = combined_data_10.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
                    
                    # 2. Definisi pemetaan nama kolom untuk output
                    column_rename_map = {
                        'namaDebitur': 'Nama Debitur/Calon Debitur',
                        'npwp': 'Nomor Identitas',
                        'tglAktaPendirian': 'Tanggal Pendirian',
                        'tanggalLahir': 'Tanggal Lahir',
                        'alamat': 'Alamat',
                        'ljkKet': 'Kreditur/Pelapor',
                        'jenisSuratBerharga': 'Jenis Surat Berharga',
                        'nilaiPasar': 'Nilai Pasar',
                        'nilaiPerolehan': 'Nilai Perolehan',
                        'nominalSb': 'Outstanding/Baki Debet',
                        'jumlahHariTunggakan': 'Hari Keterlambatan',
                        'kodeValuta': 'Valuta',
                        'kualitas': 'Kode Kolektibilitas Saat ini',
                        'kualitasKet': 'Kolektibilitas Saat ini',
                        'tahunBulan24': 'Periode Pelaporan Terakhir',
                        'urutanFile': 'File ke'
                    }
                    
                    # 3. Pemisahan data berdasarkan kondisi
                    active_fSB = merged_fSB[merged_fSB['kondisi'] == '00']
                    closed_fSB = merged_fSB[merged_fSB['kondisi'] == '02']
                    
                    # 4. Map kode jenis surat berharga ke deskripsi
                    data_df = pd.DataFrame(jenis_surat_berharga)
                    kode_to_jenis = data_df.set_index('Kode')['Jenis Surat Berharga'].to_dict()
                    
                    # 5. Definisi kolom dasar untuk kedua jenis data
                    base_columns = [
                        'namaDebitur', 'npwp', 'alamat', 'ljkKet',
                        'jenisSuratBerharga', 'nilaiPasar', 'nilaiPerolehan',
                        'nominalSb', 'jumlahHariTunggakan', 'kualitas',
                        'kualitasKet', 'tahunBulan24', 'urutanFile'
                    ]
                    
                    # Cek apakah kodeValuta harus ditambahkan ke kolom
                    columns_with_valuta = base_columns.copy()
                    
                    if 'tanggalLahir' in merged_fSB.columns:
                        columns_with_valuta.insert(2, 'tanggalLahir')
                    elif 'tglAktaPendirian' in merged_fSB.columns:
                        columns_with_valuta.insert(2, 'tglAktaPendirian')
                    
                    if 'kodeValuta' in merged_fSB.columns:
                        columns_with_valuta.insert(9, 'kodeValuta')  # Sisipkan setelah nominalSb
                    
                    # 6. Function untuk memproses dan menyimpan data
                    def process_facility_data(df, columns, table_name):
                        # Map jenis surat berharga
                        df['jenisSuratBerharga'] = df['jenisSuratBerharga'].map(
                            lambda kode: kode_to_jenis.get(kode, kode)
                        )
                        
                        # Ambil data sesuai kolom yang dibutuhkan
                        facility_data = df[columns].copy()
                        
                        # Tambahkan kolom informasi
                        facility_data['periodeData'] = json_posisiDataTerakhir
                        facility_data['username'] = username
                        facility_data['namaFileUpload'] = nama_file
                        facility_data['uploadDate'] = current_datetime
                        
                        # Insert ke database
                        columns_db = ', '.join(facility_data.columns)
                        placeholders = ', '.join(['?'] * len(facility_data.columns))
                        
                        query = f"""
                            INSERT INTO {table_name} ({columns_db})
                            VALUES ({placeholders})
                        """
                        
                        data = list(facility_data.itertuples(index=False, name=None))
                        if data:
                            cur.executemany(query, data)
                        
                        # Format data untuk output HTML
                        output_data = facility_data.rename(columns=column_rename_map)
                        output_data = output_data.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                        
                        # Tambah nomor
                        output_data.reset_index(drop=True, inplace=True)
                        output_data.insert(0, 'No', output_data.index + 1)
                        
                        if table_name == 'slik_fasilitas_aktif_surat_berharga':
                            output_data.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                            
                        return facility_data, output_data.to_html(classes="table table-striped", index=False)
                    
                    # 7. Proses data untuk active facilities
                    active_facility_5, table_data_af_5 = process_facility_data(
                        active_fSB, 
                        columns_with_valuta, 
                        'slik_fasilitas_aktif_surat_berharga'
                    )
                    
                    # 8. Proses summary data untuk active facilities
                    summary_columns = [
                        'namaDebitur', 'npwp', 'ljkKet', 'jenisSuratBerharga', 'kualitas', 'kualitasKet'
                    ]
                    
                    if active_facility_5.shape[0] > 0:
                        summary_data = active_facility_5[summary_columns].copy()
                        summary_data['periodeData'] = json_posisiDataTerakhir
                        summary_data['username'] = username
                        summary_data['namaFileUpload'] = nama_file
                        summary_data['uploadDate'] = current_datetime
                        summary_data['nomorLaporan'] = nomor_laporan
                        
                        # Rename kolom untuk summary
                        summary_rename = {
                            'namaDebitur': 'namaDebitur',
                            'npwp': 'nomorIdentitas',
                            'ljkKet': 'kreditur',
                            'jenisSuratBerharga': 'jenisPembiayaan',
                            'kualitas': 'kodeKolektibilitas',
                            'kualitasKet': 'kolektibilitas'
                        }
                        summary_data = summary_data.rename(columns=summary_rename)
                        
                        # Definisi urutan kolom
                        summary_columns_ordered = [
                            'periodeData', 'username', 'namaFileUpload', 'uploadDate',
                            'namaDebitur', 'nomorLaporan', 'nomorIdentitas',
                            'kreditur', 'jenisPembiayaan', 'kodeKolektibilitas', 'kolektibilitas'
                        ]
                        
                        summary_data = summary_data[summary_columns_ordered]
                        
                        # Insert ke database
                        summary_query = f"""
                            INSERT INTO slik_summary_fasilitas_aktif ({', '.join(summary_columns_ordered)})
                            VALUES ({', '.join(['?'] * len(summary_columns_ordered))})
                        """
                        
                        summary_values = list(summary_data.itertuples(index=False, name=None))
                        if summary_values:
                            cur.executemany(summary_query, summary_values)
                    
                    # 9. Proses data untuk closed facilities
                    closed_facility_5, table_data_cf_5 = process_facility_data(
                        closed_fSB, 
                        columns_with_valuta, 
                        'slik_fasilitas_lunas_surat_berharga'
                    )
                    
                except Exception as e:
                    conn.rollback()  # Patch: rollback on error
                    table_data_af_5 = f"Error processing active facilities: {e}"
                    table_data_cf_5 = f"Error processing closed facilities: {e}"
            
        # Update progress to 100% (completed)
        conn.commit()
        task_progress[task_id]['progress'] = 100
        task_progress[task_id]['status'] = 'completed'
        
        # Store result
        task_results[task_id] = {
            "status": "success",
            "data": list_table_data
        }
        
        # Log completion
        app.logger.info(f"Task {task_id} completed successfully")
        
        # Return all processed data
        return {
            "table_data": table_data,
            "list_table_data": list_table_data,
            "table_data_2": table_data_2,
            "table_data_3": table_data_3,
            "table_data_4": table_data_4,
            "table_data_5": table_data_5,
            "table_data_6": table_data_6,
            "table_data_7": table_data_7,
            "table_data_8": table_data_8,
            "table_data_9": table_data_9,
            "table_data_10": table_data_10,
            "table_data_11": table_data_11,
            "table_data_af_1": table_data_af_1,
            "table_data_af_2": table_data_af_2,
            "table_data_af_3": table_data_af_3,
            "table_data_af_4": table_data_af_4,
            "table_data_af_5": table_data_af_5,
            "table_data_cf_1": table_data_cf_1,
            "table_data_cf_2": table_data_cf_2,
            "table_data_cf_3": table_data_cf_3,
            "table_data_cf_4": table_data_cf_4,
            "table_data_cf_5": table_data_cf_5,
        }
    except Exception as e:
        conn.rollback()  # Patch: rollback on error
        conn.rollback()  # Rollback kalau ada error
        app.logger.error(f"[{task_id}] Error processing file: {str(e)}")
        return {
            "error": True,
            "error_type": "system_error",
            "message": f"Error processing file: {str(e)}",
            "redirect_url": "/upload-big-size"
        }

# Daftar tabel yang akan diekspor
tables = [
    "slik_summary_fasilitas_aktif",
    "slik_fasilitas_aktif_kredit_pembiayaan",
    "slik_fasilitas_aktif_bank_garansi",
    "slik_fasilitas_aktif_lainnya",
    "slik_fasilitas_aktif_lc",
    "slik_fasilitas_aktif_surat_berharga",
    "slik_fasilitas_lunas_kredit_pembiayaan",
    "slik_fasilitas_lunas_bank_garansi",
    "slik_fasilitas_lunas_lainnya",
    "slik_fasilitas_lunas_lc",
    "slik_fasilitas_lunas_surat_berharga"
]

def get_data_for_display():
    conn = get_db_connection()
    data = []

    try:
        cursor = conn.cursor()

        # Bangun query UNION ALL yang benar
        # subqueries = [f"SELECT periodeData, username, namaFileUpload, uploadDate FROM {table}" for table in tables]
        # union_query = " UNION ALL ".join(subqueries)
        query = f"""
            SELECT periodeData, namaFileUpload, uploadFolderPath, username, fullname, roleAccess, uploadDate
            FROM slik_uploader
            ORDER BY uploadDate DESC
        """

        cursor.execute(query)
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]

        for row in rows:
            item = dict(zip(columns, row))
            try:
                dt = parser.parse(str(item.get("uploadDate")))
                item["uploadDate"] = dt.strftime('%d %B %Y, %H:%M')
            except Exception as e:
                print(f"Gagal parse uploadDate: {item.get('uploadDate')}, error: {e}")
                item["uploadDate"] = str(item.get("uploadDate"))
            data.append(item)

    except Exception as e:
        print(f"Error getting display data: {e}")
    finally:
        if conn:
            conn.close()

    return data

@app.route('/progress-status/<task_id>')
def get_progress_status(task_id):
    global served_final_status
    """Get progress percentage for a task"""

    # Jika task_id kosong atau "null", anggap sudah selesai
    if task_id == "null" or not task_id:
        return jsonify({'progress': 100, 'status': 'completed'})

    # ✅ Jika task sudah selesai (baik error atau success)
    if task_id in task_results:
        result = task_results[task_id]
        status = result.get('status')

        if status == 'error':
            error_type = result.get('error_type', 'general_error')

            # Jangan set served_final_status untuk validation_error
            if error_type != 'validation_error':
                served_final_status[task_id] = True

            response_data = {
                'progress': 100,
                'status': 'error',
                'message': result.get('message', 'Unknown error'),
                'error_type': error_type,
                'is_final': error_type != 'validation_error'
            }

            # Tambahkan metadata jika ada
            metadata = task_progress.get(task_id, {}).get('temp_metadata')
            if metadata:
                response_data['metadata'] = metadata

            return jsonify(response_data)

        elif status == 'completed':
            if not served_final_status.get(task_id):
                served_final_status[task_id] = True
            return jsonify({'progress': 100, 'status': 'completed'})

    # ✅ Jika task masih dalam proses
    progress_info = task_progress.get(task_id)
    if progress_info:
        progress_value = progress_info.get('progress', 0)
        status = progress_info.get('status', 'processing').lower()

        response_data = {
            'progress': progress_value,
            'status': status
        }

        if status == 'error':
            response_data.update({
                'message': progress_info.get('message', 'Processing error occurred'),
                'error_type': progress_info.get('error_type', 'general_error'),
                'is_final': progress_info.get('error_type') != 'validation_error'
            })

        # Tambahkan metadata jika ada
        metadata = progress_info.get('temp_metadata')
        if metadata:
            response_data['metadata'] = metadata

        return jsonify(response_data)

    # ✅ Jika task tidak ditemukan tapi belum pernah diserve final status
    if not served_final_status.get(task_id):
        served_final_status[task_id] = True

    return jsonify({'progress': 100, 'status': 'completed'})

# Fungsi untuk mengekspor data tabel ke Excel (versi sederhana)
def export_to_excel(periodeData, username, namaFileUpload, uploadDate):
        
    # Format tanggal untuk query
    uploadDate_str = uploadDate
    if 'T' in uploadDate:
        uploadDate_str = uploadDate.replace('T', ' ')
    
    # Definisikan tabel dan nama sheet
    tables = [
        'slik_summary_fasilitas_aktif',
        'slik_fasilitas_aktif_kredit_pembiayaan',
        'slik_fasilitas_aktif_bank_garansi',
        'slik_fasilitas_aktif_lainnya',
        'slik_fasilitas_aktif_lc',
        'slik_fasilitas_aktif_surat_berharga',
        'slik_fasilitas_lunas_kredit_pembiayaan',
        'slik_fasilitas_lunas_bank_garansi',
        'slik_fasilitas_lunas_lainnya',
        'slik_fasilitas_lunas_lc',
        'slik_fasilitas_lunas_surat_berharga'
    ]
    
    sheet_name_mapping = {
        'slik_summary_fasilitas_aktif': 'Rangkuman Fasilitas Aktif',
        'slik_fasilitas_aktif_kredit_pembiayaan': 'Fasilitas Aktif Kredit Pembiayaan',
        'slik_fasilitas_aktif_bank_garansi': 'Fasilitas Aktif Bank Garansi',
        'slik_fasilitas_aktif_lainnya': 'Fasilitas Aktif Lainnya',
        'slik_fasilitas_aktif_lc': 'Fasilitas Aktif LC',
        'slik_fasilitas_aktif_surat_berharga': 'Fasilitas Aktif Surat Berharga',
        'slik_fasilitas_lunas_kredit_pembiayaan': 'Fasilitas Lunas Kredit Pembiayaan',
        'slik_fasilitas_lunas_bank_garansi': 'Fasilitas Lunas Bank Garansi',
        'slik_fasilitas_lunas_lainnya': 'Fasilitas Lunas Lainnya',
        'slik_fasilitas_lunas_lc': 'Fasilitas Lunas LC',
        'slik_fasilitas_lunas_surat_berharga': 'Fasilitas Lunas Surat Berharga'
    }
    
    # Mapping kolom yang umum digunakan di semua sheet
    def get_column_mapping(sheet_name):
        # Base mapping yang berlaku untuk semua sheet
        base_mapping = {
            'No': 'No',
            'namaDebitur': 'Nama Debitur/Calon Debitur',
            'npwp': 'Nomor Identitas',
            'nomorIdentitas': 'Nomor Identitas',
            'alamat': 'Alamat',
            'ljkKet': 'Kreditur/Pelapor',
            'kreditur': 'Kreditur/Pelapor',
            'plafon': 'Plafon',
            'kualitas': 'Kode Kolektibilitas Saat ini',
            'kodeKolektibilitas': 'Kode Kolektibilitas Saat ini',
            'kualitasKet': 'Kolektibilitas Saat ini',
            'kolektibilitas': 'Kolektibilitas Saat ini',
            'tahunBulan24': 'Periode Pelaporan Terakhir',
            'urutanFile': 'File ke',
            'tglAktaPendirian': 'Tanggal Pendirian',
            'tanggalLahir': 'Tanggal Lahir',
            'kodeValuta': 'Valuta',
            'valuta': 'Valuta',
            'valutaKode': 'Valuta',
            'jumlahHariTunggakan': 'Hari Keterlambatan'
        }
        
        # Mapping spesifik berdasarkan jenis sheet
        if 'Rangkuman' in sheet_name:
            specific_mapping = {
                'nomorLaporan': 'Nomor Laporan',
                'jenisPembiayaan': 'Jenis Kredit/Pembiayaan'
            }
        elif 'Kredit Pembiaya' in sheet_name:
            specific_mapping = {
                'jenisKreditPembiayaanKet': 'Jenis Kredit/Pembiayaan',
                'jenisPenggunaanKet': 'Jenis Penggunaan',
                'bakiDebet': 'Oustanding/Baki Debet',
                'tunggakanPokok': 'Tunggakan Pokok',
                'tunggakanBunga': 'Tunggakan Bunga',
                'denda': 'Denda'
            }
        elif 'LC' in sheet_name:
            specific_mapping = {
                'jenisLcKet': 'Jenis L/C',
                'tujuanLcKet': 'Tujuan L/C',
                'nominalLc': 'Oustanding/Baki Debet',
                'tanggalWanPrestasi': 'Tanggal Wan prestasi'
            }
        elif 'Bank Garansi' in sheet_name:
            specific_mapping = {
                'jenisGaransiKet': 'Jenis Garansi',
                'tujuanGaransiKet': 'Tujuan Garansi',
                'nominalBg': 'Oustanding/Baki Debet',
                'tanggalWanPrestasi': 'Tanggal Wan Prestasi'
            }
        elif 'Lainnya' in sheet_name:
            specific_mapping = {
                'jenisFasilitasKet': 'Jenis Fasilitas',
                'nominalJumlahKwajibanIDR': 'Oustanding/Baki Debet'
            }
        elif 'Surat Berharga' in sheet_name:
            specific_mapping = {
                'jenisSuratBerharga': 'Jenis Surat Berharga',
                'nilaiPasar': 'Nilai Pasar',
                'nilaiPerolehan': 'Nilai Perolehan',
                'nominalSb': 'Outstanding/Baki Debet'
            }
        else:
            specific_mapping = {}
        
        # Gabungkan base mapping dengan specific mapping
        return {**base_mapping, **specific_mapping}
    
    # Buat Excel workbook
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        workbook = writer.book
        
        # Format untuk highlight baris kuning
        highlight_format = workbook.add_format({'bg_color': '#FFFF00', 'border': 1})
        normal_format = workbook.add_format({'border': 1})
        header_format = workbook.add_format({'bold': True, 'border': 1})
        
        data_found = False
        print(f"Periode: {periodeData} username: {username} and file: {namaFileUpload}")
        for table in tables:
            try:
                query = f"""
                    SELECT * FROM {table}
                    WHERE periodeData = ? AND username = ? AND namaFileUpload = ?
                """
                cur.execute(query, (periodeData, username, namaFileUpload))

                columns = [column[0] for column in cur.description]
                rows = cur.fetchall()
                df = pd.DataFrame.from_records(rows, columns=columns)
                print(f"Found {len(df)} rows for table {table}")
                
                # Drop kolom yang tidak perlu
                drop_cols = ['periodeData', 'username', 'namaFileUpload', 'uploadDate', 'id']
                df.drop(columns=[col for col in drop_cols if col in df.columns], errors='ignore', inplace=True)

                # Validasi khusus untuk kolom tanggal - drop jika semua nilai kosong
                date_cols_to_check = ['tglAktaPendirian', 'tanggalLahir']
                for col in date_cols_to_check:
                    if col in df.columns:
                        # Cek apakah semua nilai dalam kolom kosong (None, NaN, atau string kosong)
                        if df[col].isna().all() or (df[col].astype(str).str.strip() == '').all():
                            print(f"Dropping column '{col}' - all values are empty")
                            df.drop(columns=[col], inplace=True)
                
                # Tambahkan kolom No
                df.insert(0, 'No', range(1, len(df) + 1))

                sheet_name = sheet_name_mapping.get(table, table)[:31]
                
                # Rename kolom
                mapping = get_column_mapping(sheet_name)
                rename_dict = {old: new for old, new in mapping.items() if old in df.columns}
                df.rename(columns=rename_dict, inplace=True)
                
                # Buat worksheet
                worksheet = workbook.add_worksheet(sheet_name)
                
                # Tulis header
                for col_idx, col_name in enumerate(df.columns):
                    worksheet.write(0, col_idx, col_name, header_format)
                
                # Cari kolom untuk highlight
                highlight_col = None
                for i, col_name in enumerate(df.columns):
                    if col_name == 'Kode Kolektibilitas Saat ini':
                        highlight_col = i
                        break
                
                # Tulis data dengan format kondisional
                for row_idx in range(len(df)):
                    need_highlight = False
                    if highlight_col is not None:
                        value = df.iloc[row_idx, highlight_col]
                        if pd.notna(value) and str(value) != '1':
                            need_highlight = True
                    
                    format_to_use = highlight_format if need_highlight else normal_format
                    excel_row = row_idx + 1
                    for col_idx in range(len(df.columns)):
                        worksheet.write(excel_row, col_idx, df.iloc[row_idx, col_idx], format_to_use)
                
                data_found = True
                print(f"Wrote data to sheet {sheet_name}")
            except Exception as e:
                print(f"Error on table {table}: {str(e)}")
                continue
        
        # Jika tidak ada data
        if not data_found:
            pd.DataFrame({'Message': ['No data found for the specified criteria']}).to_excel(
                writer, sheet_name='No Data', index=False)
    
    output.seek(0)
    return output
    
@app.route('/upload-big-size', methods=['GET', 'POST'])
def upload_big_size_file():
    if 'username' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    role_access = session.get('role_access')
    fullname = session.get('fullname')
    username = session.get('username')

    if request.method == 'GET':
        show_alert = session.pop('upload_done', False)
        show_processing_alert = session.pop('show_processing_alert', False)

        # Ambil data dari DB
        all_data = get_data_for_display()

        # Tambahkan task yang sedang berjalan
        in_progress_tasks = []
        for tid, v in task_progress.items():
            if v.get('status') == 'Processing' and 'temp_metadata' in v:
                v['temp_metadata']['task_id'] = tid
                in_progress_tasks.append(v['temp_metadata'])

        all_data = in_progress_tasks + all_data

        # Siapkan progres task
        current_task_progress = {}
        for item in all_data:
            if not all(key in item for key in ['username', 'namaFileUpload']):
                continue

            task_id = item.get('task_id')
            if task_id and task_id in task_progress:
                current_task_progress[task_id] = task_progress[task_id].get('progress', 100)
            else:
                key = f"{item['username']}_{item['namaFileUpload']}_"
                matched = [tid for tid, v in task_progress.items() if v.get('key', '').startswith(key)]
                if matched:
                    task_id = matched[0]
                    item['task_id'] = task_id
                    current_task_progress[task_id] = task_progress[task_id].get('progress', 0)
                else:
                    item['task_id'] = None
                    
        task_id = session.get('task_id', None)
        # Jangan hapus session jika error → biarkan JS polling dan tampilkan modal
        if not task_id or (task_id not in task_progress and task_id not in task_results):
            session.pop('task_id', None)
            task_id = None

        return render_template(
            'upload_big_size.html',
            show_alert=show_alert,
            show_processing_alert=show_processing_alert,
            data=all_data,
            flags=FLAGS,
            role_access=role_access,
            fullname=fullname,
            task_progress=current_task_progress,
            task_id=task_id
        )

    elif request.method == 'POST':
        try:
            flag = request.form.get('flag')
            nama_file = request.form.get('nama_file')
            uploaded_files = request.files.getlist('file')

            if not uploaded_files or not any(f.filename for f in uploaded_files):
                flash("No files selected for upload.")
                return redirect(url_for('upload_big_size_file'))
            
            # Validasi input
            if not flag or not nama_file or not uploaded_files:
                flash('Semua field harus diisi', 'error')
                return redirect(url_for('upload_big_size_file'))
            
            # Cek duplikasi nama file
            if check_filename_exists(nama_file):
                # flash('Nama File sudah ada, harap masukkan nama file yang lain', 'error')
                # return redirect(url_for('upload_big_size_file'))
                flash('Nama File sudah ada, harap masukkan nama file yang lain', 'error')
                return redirect(url_for('upload_big_size_file'))

            # Hitung total ukuran dan validasi ekstensi file
            total_file_size = 0
            for f in uploaded_files:
                if f and f.filename:
                    if not is_txt_file(f.filename):
                        # flash(f"File '{f.filename}' bukan file .txt. Hanya file .txt yang diperbolehkan.", "error")
                        # return redirect(url_for('upload_big_size_file'))
                        return '''
                            <script>
                                alert("File yang diupload bukan file .txt. Hanya file .txt yang diperbolehkan.");
                                window.location.href = "/upload-big-size";
                            </script>
                        '''

                    f.seek(0, 2)  # Go to end of file
                    total_file_size += f.tell()  # Get current position (file size)
                    f.seek(0)  # Reset file pointer to beginning

            if total_file_size > MAX_FILE_BIG_SIZE:
                # flash("Total file yang diupload terlalu besar. Maksimum 200MB!")
                # return redirect(url_for('upload_big_size_file'))
                return '''
                    <script>
                        alert("Total file yang diupload terlalu besar. Maksimum 200MB!");
                        window.location.href = "/upload-big-size";
                    </script>
                '''

            # Generate unique task id
            task_id = str(uuid.uuid4())
            current_datetime = datetime.now()

            # Simpan file dalam bentuk bytes
            total_file_size = 0
            temp_files = []
            for file in uploaded_files:
                if file and file.filename:
                    file_content = file.read()
                    temp_files.append({
                        'filename': file.filename,
                        'content': file_content
                    })

            # Simpan task ke queue
            user_info = {
                "username": username,
                "role_access": role_access,
                "fullname": fullname,
                "flag": flag,
                "nama_file": nama_file
            }
            
            # Masukkan ke task_progress
            task_progress[task_id] = {
                'progress': 0,
                'status': 'processing', # pastikan status awal adalah 'processing'
                'key': f"{username}_{nama_file}_{flag}",
                'temp_metadata': {
                    'username': username,
                    'namaFileUpload': nama_file,
                    'periodeData': '-',
                    'uploadDate': current_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                    'task_id': task_id,
                    'fullname': fullname
                }
            }

            # Masukkan ke queue untuk diproses
            try:
                task_queue.put_nowait((task_id, temp_files, user_info))
            except queue.Full:
                return jsonify({
                    "status": "error",
                    "message": "Antrean upload file penuh. Silakan coba lagi nanti."
                }), 503
            
            # Simpan task_id di session dan set flag upload_done
            session['task_id'] = task_id
            session['upload_done'] = False
            session['show_processing_alert'] = True
            session['temp_filename'] = nama_file
            
            return redirect(url_for('upload_big_size_file'))
        
        except Exception as e:
            print(f"Error during upload: {e}")
            # flash(f'Error during upload: {e}', 'error')
            return redirect(url_for('upload_big_size_file'))
            
@app.route('/download-big-size', methods=['GET'])
def download_big_size():
    try:
        periodeData = urllib.parse.unquote(request.args.get("periodeData", ""))
        username = session.get('username')
        namaFileUpload = urllib.parse.unquote(request.args.get("namaFileUpload", ""))
        uploadDate = urllib.parse.unquote(request.args.get("uploadDate", ""))
        downloadType = "Output Excel"
        downloadDate = datetime.now()

        conn = None
        cursor = None

        try:
            dt_obj = try_parse_upload_date(uploadDate)
            uploadDate = dt_obj.strftime("%Y-%m-%d %H:%M:%S")

            conn = get_db_connection()
            cursor = conn.cursor()

            query = """
                INSERT INTO slik_download_logging (periodeData, namaFileUpload, downloadType, username, downloadDate)
                VALUES (?, ?, ?, ?, ?)
            """
            cursor.execute(query, (periodeData, namaFileUpload, downloadType, username, downloadDate))
            conn.commit()

        except Exception as e:
            print(f"Error saving to DB: {e}")
            traceback.print_exc()
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

        print(f"Downloading Excel with parameters: {periodeData}, {username}, {namaFileUpload}, {uploadDate}")
        excel_file = export_to_excel(periodeData, username, namaFileUpload, uploadDate)

        return send_file(
            excel_file,
            as_attachment=True,
            download_name=f"{periodeData}_{namaFileUpload}.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        print(f"Error in download_excel: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/handle-upload-error/<task_id>')
def handle_upload_error(task_id):
    """Handle upload errors and redirect appropriately"""
    if task_id in task_results:
        result = task_results[task_id]
        if result.get('status') == 'error':
            error_type = result.get('error_type', 'general_error')
            error_message = result.get('error', 'Unknown error')
            redirect_url = result.get('redirect_url', '/upload-big-size')
            
            # Clean up task results after handling
            del task_results[task_id]
            if task_id in task_progress:
                del task_progress[task_id]
            
            return f'''
                <script>
                    alert("{error_message}");
                    window.location.href = "{redirect_url}";
                </script>
            '''
    
    return redirect(url_for('upload_big_size_file'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=True)
