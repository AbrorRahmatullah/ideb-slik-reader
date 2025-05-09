from io import BytesIO
import os
import re
import pandas as pd
import json
import threading
import queue
import uuid
import traceback
import base64
import pyodbc
import urllib

from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, send_file, has_request_context
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from queue import Queue
from werkzeug.datastructures import FileStorage

from config.database import get_db_connection
from functions.popup_notification import render_alert
from devtools import debug

app = Flask(__name__)
app.secret_key = 'supersecretkey'
bcrypt = Bcrypt(app)

# Configure session timeout to 10 minutes
app.permanent_session_lifetime = timedelta(hours=5)

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

# Available flags
FLAGS = ["Individual", "Perusahaan"]

# Create a global task queue and task results dictionary
task_queue = queue.Queue()
task_results = {}
task_progress = {}
conn = get_db_connection()
cur = conn.cursor()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_FILE_BIG_SIZE = 200 * 1024 * 1024  # 10MB

# --- Save to DB ---
def save_file_metadata_to_db(periodeData, namaFileUpload, fileContentBase64, username, fullname, roleAccess, uploadDate):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
            INSERT INTO slik_uploader (periodeData, namaFileUpload, fileContentBase64, username, fullname, roleAccess, uploadDate)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(query, (periodeData, namaFileUpload, fileContentBase64, username, fullname, roleAccess, uploadDate))
        conn.commit()

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
        
        try:
            bulan_dict = {
                    1: "Januari", 2: "Februari", 3: "Maret", 4: "April",
                    5: "Mei", 6: "Juni", 7: "Juli", 8: "Agustus",
                    9: "September", 10: "Oktober", 11: "November", 12: "Desember"
                }
            # Konversi files (yang berisi raw content) menjadi FileStorage objects
            periode_data = None
            uploaded_files = []
            for file_data in files:
                # Create BytesIO object with the content
                file_stream = BytesIO(file_data['content'])
                # Create a FileStorage object with this stream
                file_obj = FileStorage(
                    stream=file_stream,
                    filename=file_data['filename'],
                    name='file'
                )
                uploaded_files.append(file_obj)
                
            # Set a flag to track if we've already processed a file successfully
            first_successful_file = True

            # Process files to extract period data from first valid file
            for idx, uploaded_file in enumerate(uploaded_files):  # Fixed: enumerate returns (index, item)
                try:
                    file_content = uploaded_file.stream.read()
                    
                    # Flag to track if current file was processed successfully
                    file_processed = False
                    
                    # Try different encodings in order of likelihood
                    for encoding in ['utf-8', 'latin-1', 'utf-16', 'ascii']:
                        try:
                            # Decode and clean in one step
                            content = re.sub(r'[^\x20-\x7E\t\r\n]', '', 
                                        file_content.decode(encoding, errors='strict'))
                            
                            # Parse JSON directly
                            data = json.loads(content)
                            
                            if 'perusahaan' in data and 'posisiDataTerakhir' in data['perusahaan']:
                                posisiDataTerakhir = data['perusahaan']['posisiDataTerakhir']
                                date_obj = datetime.strptime(posisiDataTerakhir, "%Y%m")
                                json_posisiDataTerakhir = f"{bulan_dict[date_obj.month]} {date_obj.year}"
                                
                                # Only set periode_data if it's still None or if this is the first successful file
                                if periode_data is None or first_successful_file:
                                    periode_data = json_posisiDataTerakhir
                                    first_successful_file = False
                                
                                # Mark as processed successfully
                                file_processed = True
                                break  # Exit encoding loop since we found a working encoding
                                
                        except UnicodeDecodeError:
                            # Try next encoding
                            continue
                        except json.JSONDecodeError as e:
                            print(f"JSON error in file {uploaded_file.filename}: {str(e)}")
                            break
                        except KeyError as e:
                            print(f"Missing key in JSON structure: {str(e)}")
                            break
                        except Exception as e:
                            print(f"Unexpected error: {str(e)}")
                            break
                            
                    # Reset the file stream position for potential future reads
                    uploaded_file.stream.seek(0)
                    
                    if not file_processed:
                        print(f"Warning: Could not process file {uploaded_file.filename}")
                        
                except Exception as e:
                    print(f"Error processing file: {str(e)}")

            # Ensure periode_data is set to a default value if no files were processed successfully
            if periode_data is None:
                periode_data = "Unknown Period"  # Or any other default value

            # Simpan semua file metadata ke database
            for file in files:
                raw_content = file['content']
                encoded_content = base64.b64encode(raw_content).decode('utf-8')
                uploaded_at = datetime.now()

                save_file_metadata_to_db(
                    periodeData=periode_data,  # Using the extracted period data for all files
                    namaFileUpload=user_info.get("nama_file"),
                    fileContentBase64=encoded_content,
                    username=user_info.get("username"),
                    fullname=user_info.get("fullname"),
                    roleAccess=user_info.get("role_access"),
                    uploadDate=uploaded_at
                )
            
            # Log start of processing
            app.logger.info(f"Processing task {task_id} for nama file {user_info.get('nama_file')}")
            
            # Update progress to 10%
            task_progress[task_id]['progress'] = 10
            
            # Panggil fungsi process_uploaded_files dengan FileStorage objects
            result = process_uploaded_files(task_id, files, uploaded_files, user_info, uploaded_at)
            task_results[task_id] = {"status": "completed", "result": result}
        except Exception as e:
            task_results[task_id] = {"status": "error", "error": str(e)}
        task_queue.task_done()

def escape_sql(val):
    """Mencegah SQL Injection dengan mengganti ' menjadi ''."""
    return val.replace("'", "''") if isinstance(val, str) else val

# Start background worker thread
worker_thread = threading.Thread(target=process_files_worker, daemon=True)
worker_thread.start()

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
            return redirect(url_for('upload_file'))
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
            flash("New passwords do not match.")
            return render_template('change_password.html')

        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch the current hashed password from the database
        cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if not user or not bcrypt.check_password_hash(user[0], current_password):
            flash("Current password is incorrect.")
            return render_template('change_password.html')
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
    
    for idx, uploaded_file in enumerate(uploaded_files, start=1):
        progress = 10 + int(70 * (idx / total_files))
        task_progress[task_id]['progress'] = progress
        
        if uploaded_file and uploaded_file.filename.endswith('.txt'):
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
                    return {"error": "Could not decode file with supported encodings."}

                # Parse JSON dari konten
                try:
                    data = json.loads(content)
                except json.JSONDecodeError as e:
                    return {"error": f"Invalid JSON file: {e}"}
                
                conn = get_db_connection()
                cur = conn.cursor()
                
                bulan_dict = {
                    1: "Januari", 2: "Februari", 3: "Maret", 4: "April",
                    5: "Mei", 6: "Juni", 7: "Juli", 8: "Agustus",
                    9: "September", 10: "Oktober", 11: "November", 12: "Desember"
                }
                
                json_header = data['header']
                posisiDataTerakhir = data['perusahaan']['posisiDataTerakhir']
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
                        conn.commit()

                    except Exception as e:
                        print(f"Error inserting data: {e}")
                        traceback.print_exc()
                        print(f"Item: {json_header}")
                        
                uploaded_data = pd.DataFrame(json_header, index=[0])
                table_data = uploaded_data.to_html(classes="table table-striped", index=False)
                
                if 'individual' in data:
                    json_individual = data['individual']
                    json_paramPencarian = data['individual']['parameterPencarian']
                    json_dpdebitur = data['individual']['dataPokokDebitur']
                    json_rFasilitas = data['individual']['ringkasanFasilitas']
                    json_fKreditPembiayan = data['individual']['fasilitas']['kreditPembiayan']
                    json_fLC = data['individual']['fasilitas']['lc']
                    json_fGaransi = data['individual']['fasilitas']['garansiYgDiberikan']
                    json_fFasilitasLain = data['individual']['fasilitas']['fasilitasLain']
                    nomor_laporan = json_individual['nomorLaporan']

                    del json_individual['dataPokokDebitur']
                    del json_individual['parameterPencarian']
                    del json_individual['fasilitas']
                    del json_individual['ringkasanFasilitas']

                    uploaded_data_2 = pd.DataFrame(json_individual, index=[0])

                    # nomor_laporan = uploaded_data_2['nomorLaporan'].to_string(index=False)

                    uploaded_data_3 = pd.DataFrame(json_paramPencarian, index=[0])

                    for debitur in json_dpdebitur:
                        list_debitur.append(debitur)
                    uploaded_data_4 = pd.DataFrame(list_debitur)

                    uploaded_data_5 = pd.DataFrame(json_rFasilitas, index=[0])
                    
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
                    
                    if len(json_fKreditPembiayan) >0 :
                        uploaded_data_6 = pd.DataFrame(json_fKreditPembiayan)
                        uploaded_data_6.drop(columns=[col for col in columns_to_remove if col in uploaded_data_6.columns], inplace=True)
                        if len(uploaded_data_6) > 0:
                            uploaded_data_6 = uploaded_data_6.assign(**{'urutanFile': idx})
                        list_uploaded_data_6.append(uploaded_data_6)

                    if len(json_fLC) >0 :
                        uploaded_data_7 = pd.DataFrame(json_fLC)
                        uploaded_data_7.drop(columns=[col for col in columns_to_remove if col in uploaded_data_7.columns], inplace=True)
                        if len(uploaded_data_7) > 0:
                            uploaded_data_7 = uploaded_data_7.assign(**{'urutanFile': idx})
                        list_uploaded_data_7.append(uploaded_data_7)

                    if len(json_fGaransi) >0 :
                        uploaded_data_8 = pd.DataFrame(json_fGaransi)
                        uploaded_data_8.drop(columns=[col for col in columns_to_remove if col in uploaded_data_8.columns], inplace=True)
                        if len(uploaded_data_8) > 0:
                            uploaded_data_8 = uploaded_data_8.assign(**{'urutanFile': idx})
                        list_uploaded_data_8.append(uploaded_data_8)

                    if len(json_fFasilitasLain) >0 :
                        uploaded_data_9 = pd.DataFrame(json_fFasilitasLain)
                        uploaded_data_9.drop(columns=[col for col in columns_to_remove if col in uploaded_data_9.columns], inplace=True)
                        if len(uploaded_data_9) > 0:
                            uploaded_data_9 = uploaded_data_9.assign(**{'urutanFile': idx})
                        list_uploaded_data_9.append(uploaded_data_9)

                elif 'perusahaan' in data:
                    json_perusahaan = data['perusahaan']
                    json_paramPencarian =data['perusahaan']['parameterPencarian']
                    json_dpdebitur = data['perusahaan']['dataPokokDebitur']
                    json_kPengurusPemilik = data['perusahaan']['kelompokPengurusPemilik']
                    json_rFasilitas = data['perusahaan']['ringkasanFasilitas']
                    json_fKreditPembiayan = data['perusahaan']['fasilitas']['kreditPembiayan']
                    json_fSuratBerharga = data['perusahaan']['fasilitas']['suratBerharga']
                    json_fLC = data['perusahaan']['fasilitas']['lc']
                    json_fGaransi = data['perusahaan']['fasilitas']['garansiYgDiberikan']
                    json_fFasilitasLain = data['perusahaan']['fasilitas']['fasilitasLain']
                    nomor_laporan = json_perusahaan['nomorLaporan']
                    
                    del json_perusahaan['dataPokokDebitur']
                    del json_perusahaan['parameterPencarian']
                    del json_perusahaan['fasilitas']
                    del json_perusahaan['ringkasanFasilitas']
                    del json_perusahaan['kelompokPengurusPemilik']
                    
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
                        conn.commit()

                    if json_paramPencarian:
                        insert_data(cur, "slik_parameter_pencarian", json_paramPencarian, columns_to_remove, extra_columns=extra)
                        conn.commit()

                    if json_dpdebitur:
                        for item in json_dpdebitur:
                            insert_data(cur, "slik_data_pokok_debitur", item, columns_to_remove, extra_columns=extra)
                        conn.commit()

                    if json_kPengurusPemilik:
                        for kelompok in json_kPengurusPemilik:
                            for pengurus in kelompok["pengurusPemilik"]:
                                full_item = {
                                    "kodeLJK": kelompok["kodeLJK"],
                                    "namaLJK": kelompok["namaLJK"],
                                    **pengurus
                                }
                                insert_data(cur, "slik_kelompok_pengurus_pemilik", full_item, columns_to_remove, extra_columns=extra)
                        conn.commit()

                    if json_rFasilitas:
                        insert_data(cur, "slik_ringkasan_fasilitas", json_rFasilitas, columns_to_remove, extra_columns=extra)
                        conn.commit()
                          
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
                        conn.commit()

                        uploaded_data_6 = pd.DataFrame(json_fKreditPembiayan)
                        uploaded_data_6.drop(columns=[col for col in columns_to_remove if col in uploaded_data_6.columns], inplace=True)
                        if len(uploaded_data_6) > 0:
                            uploaded_data_6 = uploaded_data_6.assign(**{'urutanFile': idx})
                        list_uploaded_data_6.append(uploaded_data_6)

                    # Fasilitas LC
                    if json_fLC:
                        for item in json_fLC:
                            insert_data(cur, "slik_fasilitas_lc", item, columns_to_remove, extra_columns=extra)
                        conn.commit()

                        uploaded_data_7 = pd.DataFrame(json_fLC)
                        uploaded_data_7.drop(columns=[col for col in columns_to_remove if col in uploaded_data_7.columns], inplace=True)
                        if len(uploaded_data_7) > 0:
                            uploaded_data_7 = uploaded_data_7.assign(**{'urutanFile': idx})
                        list_uploaded_data_7.append(uploaded_data_7)

                    # Fasilitas Garansi
                    if json_fGaransi:
                        for item in json_fGaransi:
                            insert_data(cur, "slik_fasilitas_garansi", item, columns_to_remove, extra_columns=extra)
                        conn.commit()

                        uploaded_data_8 = pd.DataFrame(json_fGaransi)
                        uploaded_data_8.drop(columns=[col for col in columns_to_remove if col in uploaded_data_8.columns], inplace=True)
                        if len(uploaded_data_8) > 0:
                            uploaded_data_8 = uploaded_data_8.assign(**{'urutanFile': idx})
                        list_uploaded_data_8.append(uploaded_data_8)

                    # Fasilitas Lainnya
                    if json_fFasilitasLain:
                        for item in json_fFasilitasLain:
                            insert_data(cur, "slik_fasilitas_lainnya", item, columns_to_remove, extra_columns=extra)
                        conn.commit()

                        uploaded_data_9 = pd.DataFrame(json_fFasilitasLain)
                        uploaded_data_9.drop(columns=[col for col in columns_to_remove if col in uploaded_data_9.columns], inplace=True)
                        if len(uploaded_data_9) > 0:
                            uploaded_data_9 = uploaded_data_9.assign(**{'urutanFile': idx})
                        list_uploaded_data_9.append(uploaded_data_9)

                    # Surat Berharga
                    if json_fSuratBerharga:
                        for item in json_fSuratBerharga:
                            insert_data(cur, "slik_fasilitas_surat_berharga", item, columns_to_remove, extra_columns=extra)
                        conn.commit()

                        uploaded_data_10 = pd.DataFrame(json_fSuratBerharga)
                        uploaded_data_10.drop(columns=[col for col in columns_to_remove if col in uploaded_data_10.columns], inplace=True)
                        if len(uploaded_data_10) > 0:
                            uploaded_data_10 = uploaded_data_10.assign(**{'urutanFile': idx})
                        list_uploaded_data_10.append(uploaded_data_10)      
                                          
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
                return {"error": f"Error processing file: {e}"}
        else:
            return {"error": "Please upload a valid Text file."}
    
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

                # ACTIVE FACILITY (Kondisi == '00')
                active_fKP = merged_fKP[merged_fKP['kondisi'] == '00']
                columns = [
                    'namaDebitur', 'npwp', 'alamat', 'ljkKet',
                    'jenisKreditPembiayaanKet', 'jenisPenggunaanKet', 'plafon',
                    'bakiDebet', 'tunggakanPokok', 'tunggakanBunga', 'denda',
                    'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24', 'urutanFile'
                ]

                if 'tglAktaPendirian' in active_fKP.columns:
                    columns.insert(2, 'tglAktaPendirian')
                
                if 'valutaKode' in active_fKP.columns:
                    columns.insert(12, 'valutaKode')

                active_facility_1 = active_fKP[columns]
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
                    rename_dict['tglAktaPendirian'] = 'Tanggal Lahir/Pendirian'
                
                if 'valutaKode' in active_fKP.columns:
                    rename_dict['valutaKode'] = 'Valuta'
                    
                active_facility_1['periodeData'] = json_posisiDataTerakhir
                active_facility_1['username'] = username
                active_facility_1['namaFileUpload'] = nama_file
                active_facility_1['uploadDate'] = current_datetime
                
                # Ambil nama kolom dari DataFrame
                columns_af = ', '.join(active_facility_1.columns)

                # Placeholder SQL Server pakai '?'
                placeholders = ', '.join(['?'] * len(active_facility_1.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_aktif_kredit_pembiayaan ({columns_af})
                    VALUES ({placeholders})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(active_facility_1.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")

                active_facility_1 = active_facility_1.rename(columns=rename_dict)
                active_facility_1.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                active_facility_1 = active_facility_1.reset_index(names='No')
                active_facility_1['No'] = active_facility_1.index + 1
                active_facility_1 = active_facility_1.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_af_1 = active_facility_1.to_html(classes="table table-striped", index=False)

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
                    rename_dict_closed['tglAktaPendirian'] = 'Tanggal Lahir/Pendirian'

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
                    conn.commit()
                else:
                    print("Data kosong!")
                
                closed_facility_1 = closed_facility_1.rename(columns=rename_dict_closed)
                closed_facility_1.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)  # Added this line to match active_facility_1 treatment
                closed_facility_1 = closed_facility_1.reset_index(names='No')
                closed_facility_1['No'] = closed_facility_1.index + 1
                closed_facility_1 = closed_facility_1.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_cf_1 = closed_facility_1.to_html(classes="table table-striped", index=False)
            except Exception as e:
                table_data_af_1 = f"Error processing active facilities: {e}"
                table_data_cf_1 = f"Error processing closed facilities: {e}"
    
    if len(list_uploaded_data_7) > 0:
        missing_ljk = [i for i, df in enumerate(list_uploaded_data_7) if 'ljk' not in df.columns]
        if not missing_ljk:
            try:
                # Deduplicate `uploaded_data_4` on 'pelapor'
                uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                combined_data_7 = pd.concat(list_uploaded_data_7, ignore_index=True)
                # Merge `uploaded_data_7` with deduplicated `uploaded_data_4`
                merged_fLC = combined_data_7.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
                
                # Column renaming map
                column_rename_map = {
                    'namaDebitur': 'Nama Debitur/Calon Debitur',
                    'npwp':'Nomor Identitas',
                    'tglAktaPendirian':'Tanggal Lahir/Pendirian',
                    'alamat':'Alamat',
                    'ljkKet':'Kreditur/Pelapor',
                    'jenisLcKet':'Jenis L/C',
                    'tujuanLcKet':'Tujuan L/C',
                    'plafon':'Plafon',
                    'nominalLc':'Oustanding/Baki Debet',
                    'valuta': 'Valuta',  # Tambahkan valuta ke rename map langsung di sini
                    'tanggalWanPrestasi':'Tanggal Wan prestasi',
                    'kualitas':'Kode Kolektibilitas Saat ini',
                    'kualitasKet':'Kolektibilitas Saat ini',
                    'tahunBulan24':'Periode Pelaporan Terakhir',
                    'urutanFile': 'File ke'
                }
                
                # Process active facilities
                active_fLC = merged_fLC[merged_fLC['kondisi'] == '00']
                
                # Daftar kolom dasar
                active_columns = [
                    'namaDebitur', 'npwp', 'tglAktaPendirian', 'alamat',
                    'ljkKet', 'jenisLcKet', 'tujuanLcKet', 'plafon', 'nominalLc',
                    'tanggalWanPrestasi', 'kualitas', 'kualitasKet',
                    'tahunBulan24', 'urutanFile'
                ]
                
                # Cek dan tambahkan kolom valuta jika ada
                if 'valuta' in active_fLC.columns:
                    # Sisipkan valuta setelah nominalLc (posisi ke-9)
                    active_columns.insert(9, 'valuta')
                
                # Buat DataFrame dengan kolom yang sudah termasuk valuta jika ada
                active_facility_2 = active_fLC[active_columns]
                
                active_facility_2['periodeData'] = json_posisiDataTerakhir
                active_facility_2['username'] = username
                active_facility_2['namaFileUpload'] = nama_file
                active_facility_2['uploadDate'] = current_datetime
                
                # Ambil nama kolom dari DataFrame untuk SQL query
                columns = ', '.join(active_facility_2.columns)

                # Placeholder SQL Server pakai '?'
                placeholders = ', '.join(['?'] * len(active_facility_2.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_aktif_lc ({columns})
                    VALUES ({placeholders})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(active_facility_2.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")
                    
                active_facility_2 = active_facility_2.rename(columns=column_rename_map)
                active_facility_2.insert(1, 'Nomor Laporan', nomor_laporan)
                active_facility_2.reset_index(drop=True, inplace=True)
                active_facility_2.insert(0, 'No', range(1, len(active_facility_2) + 1))
                active_facility_2 = active_facility_2.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_af_2 = active_facility_2.to_html(classes="table table-striped", index=False)

                # Process closed facilities
                closed_fLC = merged_fLC[merged_fLC['kondisi'] == '02']
                
                # Daftar kolom dasar untuk closed facilities
                closed_columns = [
                    'namaDebitur', 'npwp', 'tglAktaPendirian', 'alamat',
                    'ljkKet', 'jenisLcKet', 'tujuanLcKet', 'plafon', 'nominalLc',
                    'tanggalWanPrestasi', 'kualitas', 'kualitasKet',
                    'tahunBulan24', 'urutanFile'
                ]
                
                # Cek dan tambahkan kolom valuta jika ada
                if 'valuta' in closed_fLC.columns:
                    # Sisipkan valuta setelah nominalLc (posisi ke-9)
                    closed_columns.insert(9, 'valuta')
                
                # Buat DataFrame dengan kolom yang sudah termasuk valuta jika ada
                closed_facility_2 = closed_fLC[closed_columns]
                
                closed_facility_2['periodeData'] = json_posisiDataTerakhir
                closed_facility_2['username'] = username
                closed_facility_2['namaFileUpload'] = nama_file
                closed_facility_2['uploadDate'] = current_datetime
                
                # Ambil nama kolom dari DataFrame untuk SQL query
                columns_closed = ', '.join(closed_facility_2.columns)

                # Placeholder SQL Server pakai '?'
                placeholders_closed = ', '.join(['?'] * len(closed_facility_2.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_lunas_lc ({columns_closed})
                    VALUES ({placeholders_closed})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(closed_facility_2.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")
                
                closed_facility_2 = closed_facility_2.rename(columns=column_rename_map)
                closed_facility_2.reset_index(drop=True, inplace=True)
                closed_facility_2.insert(0, 'No', range(1, len(closed_facility_2) + 1))
                closed_facility_2 = closed_facility_2.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_cf_2 = closed_facility_2.to_html(classes="table table-striped", index=False)
            except Exception as e:
                table_data_af_2 = f"Error processing active facilities: {e}"
                table_data_cf_2 = f"Error processing closed facilities: {e}"
                
    if len(list_uploaded_data_8) > 0:
        missing_ljk = [i for i, df in enumerate(list_uploaded_data_7) if 'ljk' not in df.columns]
        if not missing_ljk:
            try:
                # Deduplicate uploaded_data_4 on 'pelapor'
                uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                combined_data_8 = pd.concat(list_uploaded_data_8, ignore_index=True)

                # Merge uploaded_data_8 with deduplicated uploaded_data_4
                merged_fGar = combined_data_8.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
                
                # Column renaming map
                column_rename_map = {
                    'namaDebitur': 'Nama Debitur/Calon Debitur',
                    'npwp':'Nomor Identitas',
                    'tglAktaPendirian':'Tanggal Lahir/Pendirian',
                    'alamat':'Alamat',
                    'ljkKet':'Kreditur/Pelapor',
                    'jenisGaransiKet':'Jenis Garansi',
                    'tujuanGaransiKet':'Tujuan Garansi',
                    'plafon':'Plafon',
                    'nominalBg':'Oustanding/Baki Debet',
                    'valutaKode': 'Valuta',
                    'tanggalWanPrestasi':'Tanggal Wan prestasi',
                    'kualitas':'Kode Kolektibilitas Saat ini',
                    'kualitasKet':'Kolektibilitas Saat ini',
                    'tahunBulan24':'Periode Pelaporan Terakhir',
                    'urutanFile': 'File ke'
                }

                # Process active facilities
                active_fGar = merged_fGar[merged_fGar['kodeKondisi'] == '00']
                
                # Daftar kolom dasar
                active_columns = [
                    'namaDebitur','npwp','tglAktaPendirian','alamat',
                    'ljkKet','jenisGaransiKet','tujuanGaransiKet','plafon',
                    'nominalBg', 'tanggalWanPrestasi','kualitas',
                    'kualitasKet','tahunBulan24', 'urutanFile'
                ]
                
                # Cek dan tambahkan kolom valuta jika ada
                if 'valutaKode' in active_fGar.columns:
                    # Sisipkan valutaKode setelah nominalBg (posisi ke-9)
                    active_columns.insert(9, 'valutaKode')
                
                # Buat DataFrame dengan kolom yang sudah termasuk valuta jika ada
                active_facility_3 = active_fGar[active_columns]
                
                active_facility_3['periodeData'] = json_posisiDataTerakhir
                active_facility_3['username'] = username
                active_facility_3['namaFileUpload'] = nama_file
                active_facility_3['uploadDate'] = current_datetime
                
                # Ambil nama kolom dari DataFrame
                columns = ', '.join(active_facility_3.columns)

                # Placeholder SQL Server pakai '?'
                placeholders = ', '.join(['?'] * len(active_facility_3.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_aktif_bank_garansi ({columns})
                    VALUES ({placeholders})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(active_facility_3.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")
                
                active_facility_3 = active_facility_3.rename(columns=column_rename_map)
                active_facility_3.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                active_facility_3.reset_index(drop=True, inplace=True)
                active_facility_3.insert(0, 'No', active_facility_3.index + 1)
                active_facility_3 = active_facility_3.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_af_3 = active_facility_3.to_html(classes="table table-striped", index=False)

                # Process closed facilities
                closed_fGar = merged_fGar[merged_fGar['kodeKondisi'] == '02']
                
                # Daftar kolom dasar untuk closed facilities
                closed_columns = [
                    'namaDebitur','npwp','tglAktaPendirian','alamat',
                    'ljkKet','jenisGaransiKet','tujuanGaransiKet','plafon',
                    'nominalBg', 'tanggalWanPrestasi','kualitas',
                    'kualitasKet','tahunBulan24', 'urutanFile'
                ]
                
                # Cek dan tambahkan kolom valuta jika ada
                if 'valutaKode' in closed_fGar.columns:
                    # Sisipkan valutaKode setelah nominalBg (posisi ke-9)
                    closed_columns.insert(9, 'valutaKode')
                
                # Buat DataFrame dengan kolom yang sudah termasuk valuta jika ada
                closed_facility_3 = closed_fGar[closed_columns]
                
                closed_facility_3['periodeData'] = json_posisiDataTerakhir
                closed_facility_3['username'] = username
                closed_facility_3['namaFileUpload'] = nama_file
                closed_facility_3['uploadDate'] = current_datetime
            
                # Ambil nama kolom dari DataFrame
                columns_closed = ', '.join(closed_facility_3.columns)

                # Placeholder SQL Server pakai '?'
                placeholders_closed = ', '.join(['?'] * len(closed_facility_3.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_lunas_bank_garansi ({columns_closed})
                    VALUES ({placeholders_closed})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(closed_facility_3.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")
                
                closed_facility_3 = closed_facility_3.rename(columns=column_rename_map)
                closed_facility_3.reset_index(drop=True, inplace=True)
                closed_facility_3.insert(0, 'No', closed_facility_3.index + 1)
                closed_facility_3 = closed_facility_3.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_cf_3 = closed_facility_3.to_html(classes="table table-striped", index=False)
            except Exception as e:
                # Handle any exceptions gracefully
                table_data_af_3 = f"Error processing active facilities: {e}"
                table_data_cf_3 = f"Error processing closed facilities: {e}"

    if len(list_uploaded_data_9) > 0:
        missing_ljk = [i for i, df in enumerate(list_uploaded_data_9) if 'ljk' not in df.columns]
        if not missing_ljk:
            try:
                uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                combined_data_9 = pd.concat(list_uploaded_data_9, ignore_index=True)
                merged_fLain = combined_data_9.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
                
                column_rename_map = {
                    'namaDebitur': 'Nama Debitur/Calon Debitur',
                    'npwp':'Nomor Identitas',
                    'tglAktaPendirian':'Tanggal Lahir/Pendirian',
                    'alamat':'Alamat',
                    'ljkKet':'Kreditur/Pelapor',
                    'jenisFasilitasKet':'Jenis Fasilitas',
                    'nominalJumlahKwajibanIDR':'Oustanding/Baki Debet',
                    'kodeValuta':'Valuta',
                    'jumlahHariTunggakan':'Hari Keterlambatan',
                    'kualitas':'Kode Kolektibilitas Saat ini',
                    'kualitasKet':'Kolektibilitas Saat ini',
                    'tahunBulan24':'Periode Pelaporan Terakhir',
                    'urutanFile': 'File ke'
                }

                active_fLain = merged_fLain[merged_fLain['kodeKondisi'] == '00']
                
                # Daftar kolom dasar
                active_columns = [
                    'namaDebitur','npwp','tglAktaPendirian','alamat',
                    'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR',
                    'jumlahHariTunggakan', 'kualitas',
                    'kualitasKet', 'tahunBulan24', 'urutanFile'
                ]
                
                # Cek dan tambahkan kolom valuta jika ada
                if 'kodeValuta' in active_fLain.columns:
                    # Sisipkan kodeValuta setelah nominalJumlahKwajibanIDR (posisi ke-7)
                    active_columns.insert(7, 'kodeValuta')
                
                # Buat DataFrame dengan kolom yang sudah termasuk valuta jika ada
                active_facility_4 = active_fLain[active_columns]
                
                active_facility_4['periodeData'] = json_posisiDataTerakhir
                active_facility_4['username'] = username
                active_facility_4['namaFileUpload'] = nama_file
                active_facility_4['uploadDate'] = current_datetime
                
                # Ambil nama kolom dari DataFrame
                columns = ', '.join(active_facility_4.columns)

                # Placeholder SQL Server pakai '?'
                placeholders = ', '.join(['?'] * len(active_facility_4.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_aktif_lainnya ({columns})
                    VALUES ({placeholders})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(active_facility_4.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")
                
                active_facility_4 = active_facility_4.rename(columns=column_rename_map)
                active_facility_4.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                active_facility_4.reset_index(drop=True, inplace=True)
                active_facility_4.insert(0, 'No', active_facility_4.index + 1)
                active_facility_4 = active_facility_4.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_af_4 = active_facility_4.to_html(classes="table table-striped", index=False)

                closed_fLain = merged_fLain[merged_fLain['kodeKondisi'] == '02']
                
                # Daftar kolom dasar untuk closed facilities
                closed_columns = [
                    'namaDebitur','npwp','tglAktaPendirian','alamat',
                    'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR',
                    'jumlahHariTunggakan', 'kualitas',
                    'kualitasKet', 'tahunBulan24', 'urutanFile'
                ]
                
                # Cek dan tambahkan kolom valuta jika ada
                if 'kodeValuta' in closed_fLain.columns:
                    # Sisipkan kodeValuta setelah nominalJumlahKwajibanIDR (posisi ke-7)
                    closed_columns.insert(7, 'kodeValuta')
                
                closed_facility_4 = closed_fLain[closed_columns]
                
                closed_facility_4['periodeData'] = json_posisiDataTerakhir
                closed_facility_4['username'] = username
                closed_facility_4['namaFileUpload'] = nama_file
                closed_facility_4['uploadDate'] = current_datetime
                
                # Ambil nama kolom dari DataFrame
                columns_closed = ', '.join(closed_facility_4.columns)

                # Placeholder SQL Server pakai '?'
                placeholders_closed = ', '.join(['?'] * len(closed_facility_4.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_lunas_lainnya ({columns_closed})
                    VALUES ({placeholders_closed})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(closed_facility_4.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")
                
                closed_facility_4 = closed_facility_4.rename(columns=column_rename_map)
                closed_facility_4.reset_index(drop=True, inplace=True)
                closed_facility_4.insert(0, 'No', closed_facility_4.index + 1)
                closed_facility_4 = closed_facility_4.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_cf_4 = closed_facility_4.to_html(classes="table table-striped", index=False)
            except Exception as e:
                table_data_af_4 = f"Error processing active facilities: {e}"
                table_data_cf_4 = f"Error processing closed facilities: {e}"
            
    if len(list_uploaded_data_10) > 0:
        missing_ljk = [i for i, df in enumerate(list_uploaded_data_7) if 'ljk' not in df.columns]
        if not missing_ljk:
            try:
                uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                combined_data_10 = pd.concat(list_uploaded_data_10, ignore_index=True)
                merged_fSB = combined_data_10.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
                
                column_rename_map = {
                    'namaDebitur': 'Nama Debitur/Calon Debitur',
                    'npwp': 'Nomor Identitas',
                    'tglAktaPendirian': 'Tanggal Lahir/Pendirian',
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

                active_fSB = merged_fSB[merged_fSB['kondisi'] == '00']
                
                data_df = pd.DataFrame(jenis_surat_berharga)
                kode_to_jenis = data_df.set_index('Kode')['Jenis Surat Berharga'].to_dict()
                active_fSB['jenisSuratBerharga'] = active_fSB['jenisSuratBerharga'].map(
                    lambda kode: kode_to_jenis.get(kode, kode)  # Return the original kode if not found
                )
                
                # Daftar kolom dasar
                active_columns = [
                    'namaDebitur','npwp','tglAktaPendirian','alamat','ljkKet',
                    'jenisSuratBerharga','nilaiPasar','nilaiPerolehan',
                    'nominalSb','jumlahHariTunggakan','kualitas',
                    'kualitasKet','tahunBulan24','urutanFile'
                ]
                
                # Cek dan tambahkan kolom valuta jika ada
                if 'kodeValuta' in active_fSB.columns:
                    # Sisipkan kodeValuta setelah nominalSb (posisi ke-9)
                    active_columns.insert(9, 'kodeValuta')
                
                active_facility_5 = active_fSB[active_columns]
                
                active_facility_5['periodeData'] = json_posisiDataTerakhir
                active_facility_5['username'] = username
                active_facility_5['namaFileUpload'] = nama_file
                active_facility_5['uploadDate'] = current_datetime
                
                # Ambil nama kolom dari DataFrame
                columns = ', '.join(active_facility_5.columns)

                # Placeholder SQL Server pakai '?'
                placeholders = ', '.join(['?'] * len(active_facility_5.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_aktif_surat_berharga ({columns})
                    VALUES ({placeholders})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(active_facility_5.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")
                
                active_facility_5 = active_facility_5.rename(columns=column_rename_map)
                active_facility_5.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                active_facility_5.reset_index(drop=True, inplace=True)
                active_facility_5.insert(0, 'No', active_facility_5.index + 1)
                active_facility_5 = active_facility_5.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_af_5 = active_facility_5.to_html(classes="table table-striped", index=False)

                closed_fSB = merged_fSB[merged_fSB['kondisi'] == '02']
                
                closed_fSB['jenisSuratBerharga'] = closed_fSB['jenisSuratBerharga'].map(
                    lambda kode: kode_to_jenis.get(kode, kode)  # Return the original kode if not found
                )
                
                # Daftar kolom dasar untuk closed facilities
                closed_columns = [
                    'namaDebitur','npwp','tglAktaPendirian','alamat','ljkKet',
                    'jenisSuratBerharga','nilaiPasar','nilaiPerolehan',
                    'nominalSb','jumlahHariTunggakan','kualitas',
                    'kualitasKet','tahunBulan24','urutanFile'
                ]
                
                # Cek dan tambahkan kolom valuta jika ada
                if 'kodeValuta' in closed_fSB.columns:
                    # Sisipkan kodeValuta setelah nominalSb (posisi ke-9)
                    closed_columns.insert(9, 'kodeValuta')
                
                closed_facility_5 = closed_fSB[closed_columns]
                
                closed_facility_5['periodeData'] = json_posisiDataTerakhir
                closed_facility_5['username'] = username
                closed_facility_5['namaFileUpload'] = nama_file
                closed_facility_5['uploadDate'] = current_datetime
                
                # Ambil nama kolom dari DataFrame
                columns_closed = ', '.join(closed_facility_5.columns)

                # Placeholder SQL Server pakai '?'
                placeholders_closed = ', '.join(['?'] * len(closed_facility_5.columns))

                # Buat query insert
                query = f"""
                    INSERT INTO slik_fasilitas_lunas_surat_berharga ({columns_closed})
                    VALUES ({placeholders_closed})
                """
                # Ubah DataFrame ke list of tuple tanpa index
                data = list(closed_facility_5.itertuples(index=False, name=None))
                
                # Jalankan batch insert
                if data:
                    cur.executemany(query, data)
                    conn.commit()
                else:
                    print("Data kosong!")
                
                closed_facility_5 = closed_facility_5.rename(columns=column_rename_map)
                closed_facility_5.reset_index(drop=True, inplace=True)
                closed_facility_5.insert(0, 'No', closed_facility_5.index + 1)
                closed_facility_5 = closed_facility_5.drop(columns=['periodeData', 'username', 'namaFileUpload', 'uploadDate'], errors='ignore')
                table_data_cf_5 = closed_facility_5.to_html(classes="table table-striped", index=False)
            except Exception as e:
                table_data_af_5 = f"Error processing active facilities: {e}"
                table_data_cf_5 = f"Error processing closed facilities: {e}"
    
    # Update progress to 100% (completed)
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

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))
    
    role_access = session.get('role_access')
    fullname = session.get('fullname')
    username = session.get('username')
    
    flag = ''
            
    if request.method == 'GET':
        session['data_available'] = False
        return render_template(
            'upload.html',
            flags=FLAGS,
            role_access=role_access,
            fullname=fullname
        )
    elif request.method == 'POST':
        flag = request.form.get('flag')
        nama_file = request.form.get('nama_file')
        uploaded_files = request.files.getlist('file')
        total_file_size = 0
        
        for file in uploaded_files:
            file_size = len(file.read())
            file.seek(0)
            total_file_size += file_size
                      
        if total_file_size > MAX_FILE_SIZE:
            return '''
                <script>
                    alert("Total file yang diupload terlalu besar. Maksimum 200MB!");
                    window.location.href = "/upload"; // Redirect setelah alert
                </script>
            '''
        
        # Generate a unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize the task in the progress tracker
        task_progress[task_id] = {'progress': 0}
        
        # Save files as bytes
        temp_files = []
        for file in uploaded_files:
            if file and file.filename:
                # Read the file content and save it along with the filename
                file_content = file.read()
                temp_files.append({
                    'filename': file.filename,
                    'content': file_content
                })
        
        # Add task to queue
        user_info = {
            "username": username,
            "role_access": role_access,
            "fullname": fullname,
            "flag": flag,
            "nama_file": nama_file,
        }
        task_queue.put((task_id, temp_files, user_info))
        
        # Store task ID in session
        session['task_id'] = task_id
        session['data_available'] = True
        
        # Redirect to task status page
        return redirect(url_for('task_status', task_id=task_id))

@app.route('/task-status/<task_id>')
def task_status(task_id):
    """Check status of a background task"""
    # Initialize task_progress if task_id doesn't exist (handles race condition)
    if task_id not in task_progress:
        task_progress[task_id] = {'progress': 0}
    
    # Check if task has completed results
    if task_id in task_results:
        result = task_results[task_id]
        
        if result["status"] == "error":
            flash(f"Error: {result['error']}")
            return redirect(url_for('upload_file'))
        
        # Render the results using the processed data
        processed_data = result["result"]
        role_access = session.get('role_access')
        fullname = session.get('fullname')
        
        flash("File berhasil diupload!")
    
        return render_template(
            'upload.html',
            table_data=processed_data.get("table_data"),
            list_table_data=processed_data.get("list_table_data"),
            table_data_2=processed_data.get("table_data_2"),
            table_data_3=processed_data.get("table_data_3"),
            table_data_4=processed_data.get("table_data_4"),
            table_data_5=processed_data.get("table_data_5"),
            table_data_6=processed_data.get("table_data_6"),
            table_data_7=processed_data.get("table_data_7"),
            table_data_8=processed_data.get("table_data_8"),
            table_data_9=processed_data.get("table_data_9"),
            table_data_10=processed_data.get("table_data_10"),
            table_data_11=processed_data.get("table_data_11"), 
            flags=FLAGS,
            table_data_af_1=processed_data.get("table_data_af_1"), 
            table_data_af_2=processed_data.get("table_data_af_2"), 
            table_data_af_3=processed_data.get("table_data_af_3"), 
            table_data_af_4=processed_data.get("table_data_af_4"), 
            table_data_af_5=processed_data.get("table_data_af_5"), 
            table_data_cf_1=processed_data.get("table_data_cf_1"), 
            table_data_cf_2=processed_data.get("table_data_cf_2"), 
            table_data_cf_3=processed_data.get("table_data_cf_3"), 
            table_data_cf_4=processed_data.get("table_data_cf_4"), 
            table_data_cf_5=processed_data.get("table_data_cf_5"),
            role_access=role_access,
            fullname=fullname
        )
        
    # Task is still processing
    return render_template(
        'processing.html',
        task_id=task_id,
        role_access=session.get('role_access'),
        fullname=session.get('fullname')
    )

@app.route('/task-status-big-size-file/<task_id>')
def task_status_big_size_file(task_id):
    """Menampilkan status task upload besar"""
    role_access = session.get('role_access')
    fullname = session.get('fullname')

    if task_id not in task_results:
        # Task belum selesai → tampilkan halaman "sedang diproses"
        return render_template(
            'processing_big_size.html',
            task_id=task_id,
            role_access=role_access,
            fullname=fullname
        )

    result = task_results[task_id]

    if result["status"] == "error":
        flash(f"Terjadi kesalahan saat memproses file: {result['error']}")
        return redirect(url_for('upload_big_size_file'))

    # Jika berhasil → arahkan ke halaman utama upload dengan flash message
    flash("File berhasil diupload!")
    return redirect(url_for('upload_big_size_file'))

@app.route('/api/task-status/<task_id>', methods=['GET'])
def api_task_status(task_id):
    """API endpoint to check task status"""
    # Initialize task_progress if task_id doesn't exist
    if task_id not in task_progress:
        task_progress[task_id] = {'progress': 0}
    
    # Check if task is completed
    if task_id in task_results:
        result = task_results[task_id]
        if result["status"] == "error":
            return jsonify({"status": "error", "message": result["error"]})
        return jsonify({"status": "completed", "redirect": url_for('task_status', task_id=task_id)})
    
    # Task is still processing
    progress = task_progress.get(task_id, {}).get('progress', 0)
    return jsonify({"status": "processing", "progress": progress})

@app.route('/api/task-status-big-size-file/<task_id>')
def task_status_big_size_file_api(task_id):
    """API endpoint to check task status"""
    # Check if task_id is "null" (string) or None
    if task_id == "null" or not task_id:
        return jsonify({'status': 'completed'})
    
    # Check if task is in progress tracker
    if task_id in task_progress:
        progress_info = task_progress[task_id]
        status = progress_info.get('status', 'Processing')
        
        # If progress is 100%, return completed
        if progress_info.get('progress', 0) >= 100:
            return jsonify({'status': 'completed'})
        
        # Return current status
        return jsonify({'status': status})
    
    # Check if task is in results
    if task_id in task_results:
        result = task_results[task_id]
        if result.get('status') == 'error':
            return jsonify({'status': 'error', 'message': result.get('error', 'Unknown error')})
        return jsonify({'status': 'completed'})
    
    # Default to completed if not found (assume old completed task)
    return jsonify({'status': 'completed'})

@app.route('/download')
def download_file():
    if not session.get('data_available') or uploaded_data is None:
        return '''
                <script>
                    alert("No File data to Download!");
                    window.location.href = "/upload";
                </script>
            '''

    # Prepare directory and filename
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    directory = os.path.join('..', 'smi-slikreader/file_download')
    if not os.path.exists(directory):
        os.makedirs(directory)
    output_file = os.path.join(directory, f'file_{current_datetime}.xlsx')
    
    # Define facility dataframes with their sheet names
    facilities = {
        'fAktifKreditPembiayaan': active_facility_1,
        'fLunasKreditPembiayaan': closed_facility_1,
        'fAktifLC': active_facility_2,
        'fLunasLC': closed_facility_2,
        'fAktifBankGaransi': active_facility_3,
        'fLunasBankGaransi': closed_facility_3,
        'fAktifLainnya': active_facility_4,
        'fLunasLainnya': closed_facility_4,
        'fAktifSuratBerharga': active_facility_5,
        'fLunasSuratBerharga': closed_facility_5
    }
    
    # Write to Excel file
    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        for sheet_name, df in facilities.items():
            # Write empty dataframe if None
            if df is None:
                pd.DataFrame().to_excel(writer, sheet_name=sheet_name, index=False)
            else:
                df.to_excel(writer, sheet_name=sheet_name, index=False)

    return send_file(output_file, as_attachment=True)

# Daftar tabel yang akan diekspor
tables = [
    "slik_fasilitas_aktif_bank_garansi",
    "slik_fasilitas_aktif_kredit_pembiayaan",
    "slik_fasilitas_aktif_lainnya",
    "slik_fasilitas_aktif_lc",
    "slik_fasilitas_aktif_surat_berharga",
    "slik_fasilitas_lunas_bank_garansi",
    "slik_fasilitas_lunas_kredit_pembiayaan",
    "slik_fasilitas_lunas_lainnya",
    "slik_fasilitas_lunas_lc",
    "slik_fasilitas_lunas_surat_berharga"
]

def get_data_for_display():
    conn = get_db_connection()
    data = []
    
    query = """
    SELECT periodeData, username, namaFileUpload, MAX(uploadDate) as uploadDate
    FROM (
    """

    for i, table in enumerate(tables):
        query += f"SELECT periodeData, username, namaFileUpload, uploadDate FROM {table}"
        if i < len(tables) - 1:
            query += " UNION ALL "

    query += """
    ) AS combined_data
    GROUP BY periodeData, username, namaFileUpload
    ORDER BY MAX(uploadDate) DESC
    """

    df = pd.DataFrame()
    try:
        cur.execute(query)
        columns = [column[0] for column in cur.description]
        rows = cur.fetchall()
        df = pd.DataFrame.from_records(rows, columns=columns)
        data = df.to_dict(orient='records')
        
        # Convert Timestamp to ISO string
        for item in data:
            if isinstance(item.get("uploadDate"), pd.Timestamp):
                item["uploadDate"] = item["uploadDate"].isoformat()
    except Exception as e:
        print(f"Error getting display data: {str(e)}")
    finally:
        # Ensure the connection is closed after the task
        if conn:
            conn.close()

    return data

def get_filter_options():
    conn = get_db_connection()
    options = {
        'periodeData': set(),
        'username': set(),
        'namaFileUpload': set()
    }

    try:
        cursor = conn.cursor()

        query = """
        SELECT DISTINCT periodeData FROM (
        """
        for i, table in enumerate(tables):
            query += f"SELECT periodeData FROM {table}"
            if i < len(tables) - 1:
                query += " UNION ALL "
        query += ") AS combined_data ORDER BY periodeData"
        cursor.execute(query)
        options['periodeData'] = [row[0] for row in cursor.fetchall()]

        query = """
        SELECT DISTINCT username FROM (
        """
        for i, table in enumerate(tables):
            query += f"SELECT username FROM {table}"
            if i < len(tables) - 1:
                query += " UNION ALL "
        query += ") AS combined_data ORDER BY username"
        cursor.execute(query)
        options['username'] = [row[0] for row in cursor.fetchall()]

        query = """
        SELECT DISTINCT namaFileUpload FROM (
        """
        for i, table in enumerate(tables):
            query += f"SELECT namaFileUpload FROM {table}"
            if i < len(tables) - 1:
                query += " UNION ALL "
        query += ") AS combined_data ORDER BY namaFileUpload"
        cursor.execute(query)
        options['namaFileUpload'] = [row[0] for row in cursor.fetchall()]

    except Exception as e:
        print(f"Error getting filter options: {str(e)}")
    finally:
        conn.close()

    return options

@app.route('/progress-status/<task_id>')
def get_progress_status(task_id):
    """Get progress percentage for a task"""
    # Check if task_id is "null" (string) or None
    if task_id == "null" or not task_id:
        return jsonify({'progress': 100, 'status': 'Done'})
    
    # Get progress info from task_progress dictionary
    progress_info = task_progress.get(task_id)
    if progress_info:
        return jsonify({
            'progress': progress_info.get('progress', 0),
            'status': progress_info.get('status', 'Processing')
        })
    
    # If task is not in progress tracker, assume it's done
    return jsonify({'progress': 100, 'status': 'Done'})

# Fungsi untuk mengekspor data tabel ke Excel (versi sederhana)
def export_to_excel(periodeData, username, namaFileUpload, uploadDate):
        
    # Format tanggal untuk query
    uploadDate_str = uploadDate
    if 'T' in uploadDate:
        # Ganti T dengan spasi untuk konsistensi
        uploadDate_str = uploadDate.replace('T', ' ')
    
    # Definisikan tabel dan nama sheet
    tables = [
        'slik_fasilitas_aktif_bank_garansi',
        'slik_fasilitas_aktif_kredit_pembiayaan',
        'slik_fasilitas_aktif_lainnya',
        'slik_fasilitas_aktif_lc',
        'slik_fasilitas_aktif_surat_berharga',
        'slik_fasilitas_lunas_bank_garansi',
        'slik_fasilitas_lunas_kredit_pembiayaan',
        'slik_fasilitas_lunas_lainnya',
        'slik_fasilitas_lunas_lc',
        'slik_fasilitas_lunas_surat_berharga'
    ]
    
    sheet_name_mapping = {
        'slik_fasilitas_aktif_bank_garansi': 'Fasilitas Aktif Bank Garansi',
        'slik_fasilitas_aktif_kredit_pembiayaan': 'Fasilitas Aktif Kredit Pembiayaan',
        'slik_fasilitas_aktif_lainnya': 'Fasilitas Aktif Lainnya',
        'slik_fasilitas_aktif_lc': 'Fasilitas Aktif LC',
        'slik_fasilitas_aktif_surat_berharga': 'Fasilitas Aktif Surat Berharga',
        'slik_fasilitas_lunas_bank_garansi': 'Fasilitas Lunas Bank Garansi',
        'slik_fasilitas_lunas_kredit_pembiayaan': 'Fasilitas Lunas Kredit Pembiayaan',
        'slik_fasilitas_lunas_lainnya': 'Fasilitas Lunas Lainnya',
        'slik_fasilitas_lunas_lc': 'Fasilitas Lunas LC',
        'slik_fasilitas_lunas_surat_berharga': 'Fasilitas Lunas Surat Berharga'
    }
    
    # Buat Excel workbook
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        data_found = False
        for table in tables:
            try:
                query = f"""
                SELECT * FROM {table} 
                WHERE periodeData = ? AND username = ? AND namaFileUpload = ?
                """
                print(f"Querying SELECT * FROM {table} WHERE periodeData = {periodeData} AND username = {username} AND namaFileUpload = {namaFileUpload}")
                cur.execute(query, (periodeData, username, namaFileUpload))

                columns = [column[0] for column in cur.description]
                rows = cur.fetchall()
                df = pd.DataFrame.from_records(rows, columns=columns)

                print(f"Found {len(df)} rows for table {table}")
                df.drop(columns=[col for col in ['periodeData', 'username', 'namaFileUpload', 'uploadDate'] if col in df.columns], errors='ignore', inplace=True)
                if 'id' in df.columns:
                    df.rename(columns={'id': 'No'}, inplace=True)

                sheet_name = sheet_name_mapping.get(table, table)[:31]
                df.to_excel(writer, sheet_name=sheet_name, index=False)
                data_found = True
                print(f"Wrote data to sheet {sheet_name}")
            except Exception as e:
                print(f"Error on table {table}: {str(e)}")
                continue
        
        # Jika tidak ada data, buat sheet "No Data"
        if not data_found:
            pd.DataFrame({'Message': ['No data found for the specified criteria']}).to_excel(
                writer, sheet_name='No Data', index=False)
    
    # Reset pointer dan return
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
        show_alert = session.pop('upload_done', False)  # Hapus setelah ambil
        # Cek apakah ini filter search?
        periodeData_filter = request.args.get('periodeData', '')
        username_filter = request.args.get('username', '')
        namaFileUpload_filter = request.args.get('namaFileUpload', '')
        search_keyword = request.args.get('search', '').lower()
        page = int(request.args.get('page', 1))
        per_page = 10

        # Ambil semua data
        all_data = get_data_for_display()
        # Tambahkan task yang sedang berjalan dari task_progress
        in_progress_tasks = []
        for tid, v in task_progress.items():
            # Hanya tambahkan jika status masih Processing dan ada metadata
            if v.get('status') == 'Processing' and 'temp_metadata' in v:
                # Pastikan task_id disimpan dalam metadata
                v['temp_metadata']['task_id'] = tid
                in_progress_tasks.append(v['temp_metadata'])
        
        # Tambahkan task yang sedang berjalan ke awal daftar
        all_data = in_progress_tasks + all_data

        # Apply filter
        filtered_data = all_data
        if periodeData_filter:
            filtered_data = [item for item in filtered_data if item.get('periodeData') == periodeData_filter]
        if username_filter:
            filtered_data = [item for item in filtered_data if item.get('username') == username_filter]
        if namaFileUpload_filter:
            filtered_data = [item for item in filtered_data if item.get('namaFileUpload') == namaFileUpload_filter]
        if search_keyword:
            filtered_data = [item for item in filtered_data if 
                        (item.get('namaFileUpload', '').lower() and search_keyword in item['namaFileUpload'].lower()) or
                        (item.get('username', '').lower() and search_keyword in item['username'].lower()) or
                        (item.get('periodeData') and search_keyword in str(item['periodeData']).lower())]
            
        total_items = len(filtered_data)
        total_pages = (total_items + per_page - 1) // per_page
        start = (page - 1) * per_page
        end = start + per_page
        paginated_data = filtered_data[start:end]
        
        # Siapkan task_progress default
        current_task_progress = {}

        for item in paginated_data:
            # Pastikan item memiliki key yang dibutuhkan
            if not all(key in item for key in ['username', 'namaFileUpload']):
                continue
                
            task_id = item.get('task_id')

            # Jika task_id ada dan ada di task_progress
            if task_id and task_id in task_progress:
                current_task_progress[task_id] = task_progress[task_id].get('progress', 100)
            else:
                # Jika tidak ada task_id, coba cocokkan manual pakai username & namaFileUpload
                key = f"{item['username']}_{item['namaFileUpload']}_"
                matched = [tid for tid, v in task_progress.items() if v.get('key', '').startswith(key)]

                if matched:
                    task_id = matched[0]
                    item['task_id'] = task_id
                    current_task_progress[task_id] = task_progress[task_id].get('progress', 0)
                else:
                    # Jika tidak ditemukan, anggap sudah selesai
                    item['task_id'] = None
        
        # Dropdown filter options
        filter_options = get_filter_options()

        return render_template(
            'upload_big_size.html',
            show_alert=show_alert,
            data=paginated_data,
            filter_options=filter_options,
            selected_filters={
                'periodeData': periodeData_filter,
                'username': username_filter,
                'namaFileUpload': namaFileUpload_filter
            },
            search=search_keyword,
            page=page,
            total_pages=total_pages,
            flags=FLAGS,
            role_access=role_access,
            fullname=fullname,
            task_progress=current_task_progress
        )

    elif request.method == 'POST':
        flag = request.form.get('flag')
        nama_file = request.form.get('nama_file')
        uploaded_files = request.files.getlist('file')

        if not uploaded_files or not any(f.filename for f in uploaded_files):
            flash("No files selected for upload.")
            return redirect(url_for('upload_big_size_file'))

        # Hitung total ukuran
        total_file_size = 0
        for f in uploaded_files:
            if f and f.filename:
                f.seek(0, 2)  # Go to end of file
                total_file_size += f.tell()  # Get current position (file size)
                f.seek(0)  # Reset file pointer to beginning

        if total_file_size > MAX_FILE_BIG_SIZE:
            flash("Total file yang diupload terlalu besar. Maksimum 200MB!")
            return redirect(url_for('upload_big_size_file'))

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
            'status': 'Processing',
            'key': f"{username}_{nama_file}_{flag}",
            'temp_metadata': {
                'username': username,
                'namaFileUpload': nama_file,
                'uploadDate': current_datetime,
                'task_id': task_id
            }
        }

        # Masukkan ke queue untuk diproses
        task_queue.put((task_id, temp_files, user_info))
        
        # Simpan task_id di session dan set flag upload_done
        session['task_id'] = task_id
        session['upload_done'] = False  # Akan diubah menjadi True setelah proses selesai

        flash("Files are being processed in the background.")
        return redirect(url_for('upload_big_size_file'))

@app.route('/download-big-size/<periodeData>/<username>/<namaFileUpload>/<uploadDate>', methods=['GET'])
def download_excel(periodeData, username, namaFileUpload, uploadDate):
    try:
        # URL decode parameters
        periodeData = urllib.parse.unquote(periodeData)
        username = urllib.parse.unquote(username)
        namaFileUpload = urllib.parse.unquote(namaFileUpload)
        uploadDate = urllib.parse.unquote(uploadDate)
        
        # Log parameters for debugging
        print(f"Downloading Excel with parameters: {periodeData}, {username}, {namaFileUpload}, {uploadDate}")
        
        # Menyiapkan file Excel berdasarkan filter
        excel_file = export_to_excel(periodeData, username, namaFileUpload, uploadDate)
        
        # Mengirimkan file untuk diunduh
        return send_file(
            excel_file,
            as_attachment=True,
            download_name=f"{periodeData}_{namaFileUpload}.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        print(f"Error in download_excel: {str(e)}")
        traceback.print_exc()  # Print full stack trace for debugging
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
