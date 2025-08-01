import os
import re
import pandas as pd
import json
import threading
import queue
import uuid

from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, send_file, has_request_context
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage

from config.database import get_db_connection
from functions.popup_notification import render_alert
from functions.email_validation import is_valid_email
from devtools import debug

app = Flask(__name__)
app.secret_key = 'supersecretkey'
bcrypt = Bcrypt(app)

# Dummy credentials
#VALID_USERNAME = "admin"
#VALID_PASSWORD = "password123"

# Configure session timeout to 10 minutes
app.permanent_session_lifetime = timedelta(hours=1)

# Dummy user data (username: password)
# users = {
#     "user1": bcrypt.generate_password_hash("password123").decode('utf-8'),
#     "user2": bcrypt.generate_password_hash("secret456").decode('utf-8'),
#     "user3": bcrypt.generate_password_hash("power789").decode('utf-8'),
#     "user4": bcrypt.generate_password_hash("super012").decode('utf-8'),
#     "admin": bcrypt.generate_password_hash("admin789").decode('utf-8'),
# }

# Database connection function

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
MAX_FILE_SIZE = 110 * 1024 * 1024  # 110MB

# Background worker function
def process_files_worker():
    while True:
        task = task_queue.get()
        if task is None:  # Sentinel value to stop worker
            break
            
        task_id, file_data_list, user_info = task
        
        try:
            # Convert the file data back to file-like objects
            from io import BytesIO
            from werkzeug.datastructures import FileStorage
            
            uploaded_files = []
            for file_data in file_data_list:
                # Create BytesIO object with the content
                file_stream = BytesIO(file_data['content'])
                # Create a FileStorage object with this stream
                file_obj = FileStorage(
                    stream=file_stream,
                    filename=file_data['filename'],
                    name='file'
                )
                uploaded_files.append(file_obj)
            
            result = process_uploaded_files(uploaded_files, user_info)
            task_results[task_id] = {"status": "completed", "result": result}
        except Exception as e:
            task_results[task_id] = {"status": "error", "error": str(e)}
        finally:
            task_queue.task_done()

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

def process_uploaded_files(uploaded_files, user_info):
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

    for idx, uploaded_file in enumerate(uploaded_files, start=1):
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
                
                json_header = data['header']
                uploaded_data = pd.DataFrame(json_header, index=[0])
                table_data = uploaded_data.to_html(classes="table table-striped", index=False)
                
                if 'perusahaan' in data:
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
                    
                    if len(json_fKreditPembiayan) > 0:
                        uploaded_data_6 = pd.DataFrame(json_fKreditPembiayan)
                        uploaded_data_6.drop(columns=[col for col in columns_to_remove if col in uploaded_data_6.columns], inplace=True)
                        if len(uploaded_data_6) > 0:
                            uploaded_data_6 = uploaded_data_6.assign(**{'Urutan file': idx})
                        list_uploaded_data_6.append(uploaded_data_6)

                    if len(json_fLC) > 0:
                        uploaded_data_7 = pd.DataFrame(json_fLC)
                        uploaded_data_7.drop(columns=[col for col in columns_to_remove if col in uploaded_data_7.columns], inplace=True)
                        if len(uploaded_data_7) > 0:
                            uploaded_data_7 = uploaded_data_7.assign(**{'Urutan file': idx})
                        list_uploaded_data_7.append(uploaded_data_7)
                        
                    if len(json_fGaransi) >0 :
                        uploaded_data_8 = pd.DataFrame(json_fGaransi)
                        uploaded_data_8.drop(columns=[col for col in columns_to_remove if col in uploaded_data_8.columns], inplace=True)
                        if len(uploaded_data_8) > 0:
                            uploaded_data_8 = uploaded_data_8.assign(**{'Urutan file': idx})
                        list_uploaded_data_8.append(uploaded_data_8)

                    if len(json_fFasilitasLain) >0 :
                        uploaded_data_9 = pd.DataFrame(json_fFasilitasLain)
                        uploaded_data_9.drop(columns=[col for col in columns_to_remove if col in uploaded_data_9.columns], inplace=True)
                        if len(uploaded_data_9) > 0:
                            uploaded_data_9 = uploaded_data_9.assign(**{'Urutan file': idx})
                        list_uploaded_data_9.append(uploaded_data_9)

                    if len(json_fSuratBerharga) >0 :
                        uploaded_data_10 = pd.DataFrame(json_fSuratBerharga)
                        uploaded_data_10.drop(columns=[col for col in columns_to_remove if col in uploaded_data_10.columns], inplace=True)
                        if len(uploaded_data_10) > 0:
                            uploaded_data_10 = uploaded_data_10.assign(**{'Urutan file': idx})
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
                    'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24', 'Urutan file'
                ]

                if 'tglAktaPendirian' in active_fKP.columns:
                    columns.insert(2, 'tglAktaPendirian')

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
                    'Urutan file': 'File ke'
                }

                if 'tglAktaPendirian' in active_fKP.columns:
                    rename_dict['tglAktaPendirian'] = 'Tanggal Lahir/Pendirian'

                active_facility_1 = active_facility_1.rename(columns=rename_dict)
                active_facility_1.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                active_facility_1 = active_facility_1.reset_index(names='No')
                active_facility_1['No'] = active_facility_1.index + 1
                table_data_af_1 = active_facility_1.to_html(classes="table table-striped", index=False)

                # CLOSED FACILITY (Kondisi == '02')
                closed_fKP = merged_fKP[merged_fKP['kondisi'] == '02']
                columns_closed = [
                    'namaDebitur', 'npwp', 'alamat', 'ljkKet',
                    'jenisKreditPembiayaanKet', 'jenisPenggunaanKet', 'plafon',
                    'bakiDebet', 'tunggakanPokok', 'tunggakanBunga', 'denda',
                    'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24', 'Urutan file'
                ]

                if 'tglAktaPendirian' in closed_fKP.columns:
                    columns_closed.insert(2, 'tglAktaPendirian')

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
                    'Urutan file': 'File ke'
                }

                if 'tglAktaPendirian' in closed_fKP.columns:
                    rename_dict_closed['tglAktaPendirian'] = 'Tanggal Lahir/Pendirian'

                closed_facility_1 = closed_facility_1.rename(columns=rename_dict_closed)
                closed_facility_1 = closed_facility_1.reset_index(names='No')
                closed_facility_1['No'] = closed_facility_1.index + 1
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
                    'tanggalWanPrestasi':'Tanggal Wan prestasi',
                    'kualitas':'Kode Kolektibilitas Saat ini',
                    'kualitasKet':'Kolektibilitas Saat ini',
                    'tahunBulan24':'Periode Pelaporan Terakhir',
                    'Urutan file': 'File ke'
                }
                
                # Process active facilities
                active_fLC = merged_fLC[merged_fLC['kondisi'] == '00']
                
                active_facility_2 = (
                    active_fLC[
                        [
                            'namaDebitur','npwp','tglAktaPendirian','alamat',
                            'ljkKet','jenisLcKet','tujuanLcKet','plafon','nominalLc',
                            'tanggalWanPrestasi', 'kualitas', 'kualitasKet',
                            'tahunBulan24', 'Urutan file'
                        ]
                    ].rename(columns=column_rename_map))
                active_facility_2.insert(1, 'Nomor Laporan', nomor_laporan)
                active_facility_2.reset_index(drop=True, inplace=True)
                active_facility_2.insert(0, 'No', range(1, len(active_facility_2) + 1))
                table_data_af_2 = active_facility_2.to_html(classes="table table-striped", index=False)

                # Process closed facilities
                closed_fLC = merged_fLC[merged_fLC['kondisi'] == '02']
                
                closed_facility_2 = (
                    closed_fLC[
                        [
                            'namaDebitur','npwp','tglAktaPendirian','alamat',
                            'ljkKet','jenisLcKet','tujuanLcKet','plafon','nominalLc',
                            'tanggalWanPrestasi', 'kualitas', 'kualitasKet',
                            'tahunBulan24', 'Urutan file'
                        ]
                    ].rename(columns=column_rename_map))
                closed_facility_2.reset_index(drop=True, inplace=True)
                closed_facility_2.insert(0, 'No', range(1, len(closed_facility_2) + 1))
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
                        'tanggalWanPrestasi':'Tanggal Wan prestasi',
                        'kualitas':'Kode Kolektibilitas Saat ini',
                        'kualitasKet':'Kolektibilitas Saat ini',
                        'tahunBulan24':'Periode Pelaporan Terakhir',
                        'Urutan file': 'File ke'
                    }

                    # Process active facilities
                    active_fGar = merged_fGar[merged_fGar['kodeKondisi'] == '00']
                    
                    active_facility_3 = (
                        active_fGar[
                            [
                                'namaDebitur','npwp','tglAktaPendirian','alamat',
                                'ljkKet','jenisGaransiKet','tujuanGaransiKet','plafon',
                                'nominalBg', 'tanggalWanPrestasi','kualitas',
                                'kualitasKet','tahunBulan24', 'Urutan file'
                            ]
                        ].rename(columns=column_rename_map))
                    active_facility_3.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                    active_facility_3.reset_index(drop=True, inplace=True)
                    active_facility_3.insert(0, 'No', active_facility_3.index + 1)
                    table_data_af_3 = active_facility_3.to_html(classes="table table-striped", index=False)

                    # Process closed facilities
                    closed_fGar = merged_fGar[merged_fGar['kodeKondisi'] == '02']
                    
                    closed_facility_3 = (
                        closed_fGar[
                            [
                                'namaDebitur','npwp','tglAktaPendirian','alamat',
                                'ljkKet','jenisGaransiKet','tujuanGaransiKet','plafon',
                                'nominalBg', 'tanggalWanPrestasi','kualitas',
                                'kualitasKet','tahunBulan24', 'Urutan file'
                            ]
                        ].rename(columns=column_rename_map))
                    closed_facility_3.reset_index(drop=True, inplace=True)
                    closed_facility_3.insert(0, 'No', closed_facility_3.index + 1)
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
                    'jumlahHariTunggakan':'Hari Keterlambatan',
                    'kualitas':'Kode Kolektibilitas Saat ini',
                    'kualitasKet':'Kolektibilitas Saat ini',
                    'tahunBulan24':'Periode Pelaporan Terakhir',
                    'Urutan file': 'File ke'
                }

                active_fLain = merged_fLain[merged_fLain['kodeKondisi'] == '00']
                
                active_facility_4 = (
                    active_fLain[
                        [
                            'namaDebitur','npwp','tglAktaPendirian','alamat',
                            'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR',
                            'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24', 'Urutan file'
                        ]
                    ].rename(columns=column_rename_map))
                
                active_facility_4.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                active_facility_4.reset_index(drop=True, inplace=True)
                active_facility_4.insert(0, 'No', active_facility_4.index + 1)
                table_data_af_4 = active_facility_4.to_html(classes="table table-striped", index=False)

                closed_fLain = merged_fLain[merged_fLain['kodeKondisi'] == '02']
                
                closed_facility_4 = (
                    closed_fLain[
                        [
                            'namaDebitur','npwp','tglAktaPendirian','alamat',
                            'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR',
                            'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24', 'Urutan file'
                        ]
                    ].rename(columns=column_rename_map))
                closed_facility_4.reset_index(drop=True, inplace=True)
                closed_facility_4.insert(0, 'No', closed_facility_4.index + 1)
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
                    'kualitas': 'Kode Kolektibilitas Saat ini',
                    'kualitasKet': 'Kolektibilitas Saat ini',
                    'tahunBulan24': 'Periode Pelaporan Terakhir',
                    'Urutan file': 'File ke'
                }

                active_fSB = merged_fSB[merged_fSB['kondisi'] == '00']
                
                data_df = pd.DataFrame(jenis_surat_berharga)
                kode_to_jenis = data_df.set_index('Kode')['Jenis Surat Berharga'].to_dict()
                active_fSB['jenisSuratBerharga'] = active_fSB['jenisSuratBerharga'].map(
                    lambda kode: kode_to_jenis.get(kode, kode)  # Return the original kode if not found
                )
                active_facility_5 = (
                    active_fSB[
                        [
                            'namaDebitur','npwp','tglAktaPendirian','alamat','ljkKet',
                            'jenisSuratBerharga','nilaiPasar','nilaiPerolehan',
                            'nominalSb','jumlahHariTunggakan','kualitas',
                            'kualitasKet','tahunBulan24','Urutan file'
                        ]
                    ].rename(columns=column_rename_map))
                
                active_facility_5.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                active_facility_5.reset_index(drop=True, inplace=True)
                active_facility_5.insert(0, 'No', active_facility_5.index + 1)
                table_data_af_5 = active_facility_5.to_html(classes="table table-striped", index=False)

                closed_fSB = merged_fSB[merged_fSB['kondisi'] == '02']
                
                closed_facility_5 = (
                    closed_fSB[
                        [
                            'namaDebitur','npwp','tglAktaPendirian','alamat','ljkKet',
                            'jenisSuratBerharga','nilaiPasar','nilaiPerolehan',
                            'nominalSb','jumlahHariTunggakan','kualitas',
                            'kualitasKet','tahunBulan24','Urutan file'
                        ]
                    ].rename(columns=column_rename_map))
                closed_facility_5.reset_index(drop=True, inplace=True)
                closed_facility_5.insert(0, 'No', closed_facility_5.index + 1)
                table_data_cf_5 = closed_facility_5.to_html(classes="table table-striped", index=False)
            except Exception as e:
                table_data_af_5 = f"Error processing active facilities: {e}"
                table_data_cf_5 = f"Error processing closed facilities: {e}"
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
    
    flag = ''

    # nomor_laporan = ''
            
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
        # uploaded_file = request.files['file']
        uploaded_files = request.files.getlist('file')
        total_file_size = 0
        
        for file in uploaded_files:
            file_size = len(file.read())
            file.seek(0)
            total_file_size += file_size
                      
        if total_file_size > MAX_FILE_SIZE:
            return '''
                <script>
                    alert("Total file yang diupload terlalu besar. Maksimum 110MB!");
                    window.location.href = "/upload"; // Redirect setelah alert
                </script>
            '''
        
        # Generate a unique task ID
        task_id = str(uuid.uuid4())
        
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
            "role_access": role_access,
            "fullname": fullname,
            "flag": flag
        }
        task_queue.put((task_id, temp_files, user_info))
        
        # Store task ID in session
        session['task_id'] = task_id
        session['data_available'] = True
        
        flash("Files are being processed in the background.")
        return redirect(url_for('task_status', task_id=task_id))

@app.route('/task-status/<task_id>')
def task_status(task_id):
    """Check status of a background task"""
    if task_id not in task_results:
        return render_template(
            'processing.html',
            task_id=task_id,
            role_access=session.get('role_access'),
            fullname=session.get('fullname')
        )
    
    result = task_results[task_id]
    debug(result)
    
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

@app.route('/api/task-status/<task_id>', methods=['GET'])
def api_task_status(task_id):
    """API endpoint to check task status"""
    if task_id not in task_results:
        return jsonify({"status": "processing"})
    
    result = task_results[task_id]
    if result["status"] == "error":
        return jsonify({"status": "error", "message": result["error"]})
    
    return jsonify({"status": "completed", "redirect": url_for('task_status', task_id=task_id)})

# Download Route
@app.route('/download')
def download_file():
    
    df = pd.DataFrame()
    
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

    if not session.get('data_available') or uploaded_data is None:
        return '''
                <script>
                    alert("No File data to Download!");
                    window.location.href = "/upload"; // Redirect setelah alert
                </script>
            '''

    # Save DataFrame to Excel file
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    directory = os.path.join('..', 'smi-slikreader/file_download')
    output_file = os.path.join(directory, f'file_{current_datetime}.xlsx')
    
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        """
        uploaded_data.to_excel(writer, sheet_name='header', index=False)
        if flag == "Individual":
            uploaded_data_2.to_excel(writer, sheet_name='individual', index=False)
        elif flag == "Perusahaan":
            uploaded_data_2.to_excel(writer, sheet_name='perusahaan', index=False)
        uploaded_data_3.to_excel(writer, sheet_name='paramPencarian', index=False)
        uploaded_data_4.to_excel(writer, sheet_name='dataPokokDebitur', index=False)
        uploaded_data_5.to_excel(writer, sheet_name='ringkasanFasilitas', index=False)
        if uploaded_data_6 is None:
            upload_data_6 = pd.DataFrame()
        else:
            uploaded_data_6.to_excel(writer, sheet_name='fasilitasKreditPembiayaan', index=False)
        if uploaded_data_7 is None:
            uploaded_data_7 = pd.DataFrame()
        else:
            uploaded_data_7.to_excel(writer, sheet_name='fasilitasLC', index=False)
        if uploaded_data_8 is None:
            uploaded_data_8 = pd.DataFrame()
        else:        
            uploaded_data_8.to_excel(writer, sheet_name='fasilitasGaransi', index=False)
        if uploaded_data_9 is None:
            uploaded_data_9 = pd.DataFrame()
        else:
            uploaded_data_9.to_excel(writer, sheet_name='fasilitasFasilitasLain', index=False)
        if uploaded_data_10 is None:
            uploaded_data_10 = pd.DataFrame()
        else:
            uploaded_data_10.to_excel(writer, sheet_name='fasilitasSuratBerharga', index=False)
        if uploaded_data_11 is None:
            uploaded_data_11 = pd.DataFrame()
        else:
            uploaded_data_11.to_excel(writer, sheet_name='pengurusPemilik', index=False)
        """
        if active_facility_1 is None:
            active_facility_1 = pd.DataFrame()
        else:
            active_facility_1.to_excel(writer, sheet_name='fAktifKreditPembiayaan', index=False)
        if closed_facility_1 is None:
            closed_facility_1 = pd.DataFrame()
        else:
            closed_facility_1.to_excel(writer, sheet_name='fLunasKreditPembiayaan', index=False)
        if active_facility_2 is None:
            active_facility_2 = pd.DataFrame()
        else:
            active_facility_2.to_excel(writer, sheet_name='fAktifLC', index=False)
        if closed_facility_2 is None:
            closed_facility_2 = pd.DataFrame()
        else:
            closed_facility_2.to_excel(writer, sheet_name='fLunasLC', index=False)
        if active_facility_3 is None:
            active_facility_3 = pd.DataFrame()
        else:
            active_facility_3.to_excel(writer, sheet_name='fAktifBankGaransi', index=False)
        if closed_facility_3 is None:
            closed_facility_3 = pd.DataFrame()
        else:
            closed_facility_3.to_excel(writer, sheet_name='fLunasBankGaransi', index=False)
        if active_facility_4 is None:
            active_facility_4 = pd.DataFrame()
        else:
            active_facility_4.to_excel(writer, sheet_name='fAktifLainnya', index=False)
        if closed_facility_4 is None:
            closed_facility_4 = pd.DataFrame()
        else:
            closed_facility_4.to_excel(writer, sheet_name='fLunasLainnya', index=False)
        if active_facility_5 is None:
            active_facility_5 = pd.DataFrame()
        else:
            active_facility_5.to_excel(writer, sheet_name='fAktifSuratBerharga', index=False)
        if closed_facility_5 is None:
            closed_facility_5 = pd.DataFrame()
        else:
            closed_facility_5.to_excel(writer, sheet_name='fLunasSuratBerharga', index=False)


    return send_file(output_file, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
