from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import pandas as pd
import json
import os
from flask_bcrypt import Bcrypt
from datetime import timedelta

import psycopg2

app = Flask(__name__)
app.secret_key = 'supersecretkey'
bcrypt = Bcrypt(app)

# Dummy credentials
#VALID_USERNAME = "admin"
#VALID_PASSWORD = "password123"

# Configure session timeout to 10 minutes
app.permanent_session_lifetime = timedelta(minutes=10)

# Dummy user data (username: password)
# users = {
#     "user1": bcrypt.generate_password_hash("password123").decode('utf-8'),
#     "user2": bcrypt.generate_password_hash("secret456").decode('utf-8'),
#     "user3": bcrypt.generate_password_hash("power789").decode('utf-8'),
#     "user4": bcrypt.generate_password_hash("super012").decode('utf-8'),
#     "admin": bcrypt.generate_password_hash("admin789").decode('utf-8'),
# }

# Database connection function
def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),  # Load from .env
        user=os.getenv("DB_USER"),    # Load from .env
        password=os.getenv("DB_PASSWORD"),  # Load from .env
        host=os.getenv("DB_HOST"),    # Load from .env
        port=os.getenv("DB_PORT")     # Load from .env
    )

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

        if password != password_confirm:
            flash("Passwords do not match.")
            return render_template('register.html', username=username, role_access=role_access)
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Check if the username already exists
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            flash("Username already exists.")
            return render_template('register.html', username=username, role_access=role_access)
        else:
            # Insert new user into the database
            cur.execute("INSERT INTO users (username, password_hash, role_access, fullname, email, created_date) VALUES (%s, %s, %s, %s, %s, NOW())", (username, password_hash, role_access, fullname, email))
            conn.commit()
            flash("User registered successfully.")
            return redirect(url_for('login'))  # Redirect to login page after successful registration

        cur.close()
        conn.close()

    return render_template('register.html')

# Login Route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch the hashed password from the database for the given username
        cur.execute("SELECT password_hash, role_access FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user and bcrypt.check_password_hash(user[0], password):
            session.permanent = True
            session['username'] = username
            session['role_access'] = user[1]
            return redirect(url_for('upload_file'))
        else:
            flash("Invalid username or password.")
    
    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

# File Upload Route
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
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

    if 'username' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))
    
    role_access = session.get('role_access')
    # debug(json.dumps(dict(session), indent=4))

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

    nomor_laporan = ''

    columns_to_remove = ['agunan', 'penjamin']

    if request.method == 'POST':
        flag = request.form.get('flag')
        uploaded_file = request.files['file']

        if uploaded_file and uploaded_file.filename.endswith('.txt'):
            try:
                # Load JSON data
                #data = json.load(uploaded_file)
                try:
                    # Read content with specified encoding
                    content = uploaded_file.stream.read().decode('utf-8-sig')  
                    data = json.loads(content)
                except UnicodeDecodeError as e:
                    return f"Encoding error: {e}"
                except json.JSONDecodeError as e:
                    return f"Invalid JSON file: {e}"
                
                json_header = data['header']

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

                    del json_individual['dataPokokDebitur']
                    del json_individual['parameterPencarian']
                    del json_individual['fasilitas']
                    del json_individual['ringkasanFasilitas']

                    uploaded_data_2 = pd.DataFrame(json_individual, index=[0])
                    table_data_2 = uploaded_data_2.to_html(classes="table table-striped", index=False)

                    nomor_laporan = uploaded_data_2['nomorLaporan'].to_string(index=False)

                    uploaded_data_3 = pd.DataFrame(json_paramPencarian, index=[0])
                    table_data_3 = uploaded_data_3.to_html(classes="table table-striped", index=False)

                    uploaded_data_4 = pd.DataFrame(json_dpdebitur)
                    table_data_4 = uploaded_data_4.to_html(classes="table table-striped", index=False)

                    uploaded_data_5 = pd.DataFrame(json_rFasilitas, index=[0])
                    table_data_5 = uploaded_data_5.to_html(classes="table table-striped", index=False)

                    uploaded_data_6 = pd.DataFrame(json_fKreditPembiayan)
                    uploaded_data_6.drop(columns=[col for col in columns_to_remove if col in uploaded_data_6.columns], inplace=True)
                    table_data_6 = uploaded_data_6.to_html(classes="table table-striped", index=False)

                    if len(uploaded_data_6)>0:
                        merged_fKP = uploaded_data_6.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fKP = merged_fKP[merged_fKP['kondisi']=='00']
                        active_facility_1 = active_fKP[['namaDebitur','noIdentitas','tanggalLahir','alamat', 'ljkKet', 'jenisKreditPembiayaanKet', 'jenisPenggunaanKet', 'plafon', 'bakiDebet', 'tunggakanPokok', 'tunggakanBunga', 'denda', 'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','noIdentitas':'Nomor Identitas','tanggalLahir':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisKreditPembiayaanKet':'Jenis Kredit/Pembiayaan', 'jenisPenggunaanKet':'Jenis Penggunaan', 'plafon':'Plafon', 'bakiDebet':'Oustanding/Baki Debet', 'tunggakanPokok':'Tunggakan Pokok', 'tunggakanBunga':'Tunggakan Bunga', 'denda':'Denda', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #namaDebitur		npwp	tglAktaPendirian	alamat	ljkKet	jenisKreditPembiayaanKet	jenisPenggunaanKet	plafon	bakiDebet	tunggakanPokok	tunggakanBunga	denda	jumlahHariTunggakan	kualitasKet	tahun	bulan
                        #Nama Debitur/Calon Debitur	Nomor Laporan	Nomor Identitas	Tanggal Lahir/Pendirian	Alamat	Kreditur/Pelapor	Jenis Kredit/Pembiayaan 	Jenis Penggunaan 	Plafon	Oustanding/Baki Debet	Tunggakan Pokok	Tunggakan Bunga	Denda	Hari Keterlambatan	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_1.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_1 = active_facility_1.reset_index(names='No')
                        active_facility_1['No'] = active_facility_1.index+1
                        table_data_af_1 = active_facility_1.to_html(classes="table table-striped", index=False)

                        closed_fKP = merged_fKP[merged_fKP['kondisi']=='02']
                        closed_facility_1 = closed_fKP[['namaDebitur','noIdentitas','tanggalLahir','alamat', 'ljkKet', 'jenisKreditPembiayaanKet', 'jenisPenggunaanKet', 'plafon', 'bakiDebet', 'tunggakanPokok', 'tunggakanBunga', 'denda', 'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','noIdentitas':'Nomor Identitas','tanggalLahir':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisKreditPembiayaanKet':'Jenis Kredit/Pembiayaan', 'jenisPenggunaanKet':'Jenis Penggunaan', 'plafon':'Plafon', 'bakiDebet':'Oustanding/Baki Debet', 'tunggakanPokok':'Tunggakan Pokok', 'tunggakanBunga':'Tunggakan Bunga', 'denda':'Denda', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_1 = closed_facility_1.reset_index(names='No')
                        closed_facility_1['No'] = closed_facility_1.index+1
                        table_data_cf_1 = closed_facility_1.to_html(classes="table table-striped", index=False)

                    uploaded_data_7 = pd.DataFrame(json_fLC)
                    uploaded_data_7.drop(columns=[col for col in columns_to_remove if col in uploaded_data_7.columns], inplace=True)
                    table_data_7 = uploaded_data_7.to_html(classes="table table-striped", index=False)

                    if len(uploaded_data_7)>0:
                        merged_fLC = uploaded_data_7.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fLC = merged_fLC[merged_fLC['kondisi']=='00']
                        active_facility_2 = active_fLC[['namaDebitur','noIdentitas','tanggalLahir','alamat', 'ljkKet', 'jenisLcKet', 'tujuanLcKet', 'plafon', 'nominalLc', 'tanggalWanPrestasi', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','noIdentitas':'Nomor Identitas','tanggalLahir':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisLcKet':'Jenis L/C', 'tujuanLcKet':'Tujuan L/C', 'plafon':'Plafon', 'nominalLc':'Oustanding/Baki Debet', 'tanggalWanPrestasi':'Tanggal Wan prestasi', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #ljkKet	jenisLcKet	tujuanLcKet	plafon	nominalLc	tanggalWanPrestasi	kualitasKet	tahunBulan24
                        #Kreditur/Pelapor	Jenis L/C	Tujuan L/C	Plafon	Oustanding/Baki Debet	Tanggal Wan prestasi	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_2.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_2 = active_facility_2.reset_index(names='No')
                        active_facility_2['No'] = active_facility_2.index+1
                        table_data_af_2 = active_facility_2.to_html(classes="table table-striped", index=False)

                        closed_fLC = merged_fLC[merged_fLC['kondisi']=='02']
                        closed_facility_2 = closed_fLC[['namaDebitur','noIdentitas','tanggalLahir','alamat', 'ljkKet', 'jenisLcKet', 'tujuanLcKet', 'plafon', 'nominalLc', 'tanggalWanPrestasi', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','noIdentitas':'Nomor Identitas','tanggalLahir':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisLcKet':'Jenis L/C', 'tujuanLcKet':'Tujuan L/C', 'plafon':'Plafon', 'nominalLc':'Oustanding/Baki Debet', 'tanggalWanPrestasi':'Tanggal Wan prestasi', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_2 = closed_facility_2.reset_index(names='No')
                        closed_facility_2['No'] = closed_facility_2.index+1
                        table_data_cf_2 = closed_facility_2.to_html(classes="table table-striped", index=False)

                    uploaded_data_8 = pd.DataFrame(json_fGaransi)
                    uploaded_data_8.drop(columns=[col for col in columns_to_remove if col in uploaded_data_8.columns], inplace=True)
                    table_data_8 = uploaded_data_8.to_html(classes="table table-striped", index=False)

                    if len(uploaded_data_8)>0:
                        merged_fGar = uploaded_data_8.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fGar = merged_fGar[merged_fGar['kodeKondisi']=='00']
                        active_facility_3 = active_fGar[['namaDebitur','noIdentitas','tanggalLahir','alamat', 'ljkKet', 'jenisGaransiKet', 'tujuanGaransiKet', 'plafon', 'nominalBg', 'tanggalWanPrestasi', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','noIdentitas':'Nomor Identitas','tanggalLahir':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisGaransiKet':'Jenis Garansi', 'tujuanGaransiKet':'Tujuan Garansi', 'plafon':'Plafon', 'nominalBg':'Oustanding/Baki Debet', 'tanggalWanPrestasi':'Tanggal Wan prestasi', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #ljkKet	jenisGaransiKet	tujuanGaransiKet	plafon	nominalBg	tanggalWanPrestasi	kualitasKet	tahunBulan24
                        #Kreditur/Pelapor	Jenis Garansi	Tujuan Garansi	Plafon	Oustanding/Baki Debet	Tanggal Wan prestasi	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_3.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_3 = active_facility_3.reset_index(names='No')
                        active_facility_3['No'] = active_facility_3.index+1
                        table_data_af_3 = active_facility_3.to_html(classes="table table-striped", index=False)

                        closed_fGar = merged_fGar[merged_fGar['kodeKondisi']=='02']
                        closed_facility_3 = closed_fGar[['namaDebitur','noIdentitas','tanggalLahir','alamat', 'ljkKet', 'jenisGaransiKet', 'tujuanGaransiKet', 'plafon', 'nominalBg', 'tanggalWanPrestasi', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','noIdentitas':'Nomor Identitas','tanggalLahir':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisGaransiKet':'Jenis Garansi', 'tujuanGaransiKet':'Tujuan Garansi', 'plafon':'Plafon', 'nominalBg':'Oustanding/Baki Debet', 'tanggalWanPrestasi':'Tanggal Wan prestasi', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_3 = closed_facility_3.reset_index(names='No')
                        closed_facility_3['No'] = closed_facility_3.index+1
                        table_data_cf_3 = closed_facility_3.to_html(classes="table table-striped", index=False)

                    uploaded_data_9 = pd.DataFrame(json_fFasilitasLain)
                    uploaded_data_9.drop(columns=[col for col in columns_to_remove if col in uploaded_data_9.columns], inplace=True)
                    table_data_9 = uploaded_data_9.to_html(classes="table table-striped", index=False)

                    if len(uploaded_data_9)>0:
                        #print(uploaded_data_9)
                        merged_fLain = uploaded_data_9.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fLain = merged_fLain[merged_fLain['kodeKondisi']=='00']
                        active_facility_4 = active_fLain[['namaDebitur','noIdentitas','tanggalLahir','alamat', 'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR','jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','noIdentitas':'Nomor Identitas','tanggalLahir':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisFasilitasKet':'Jenis Fasilitas', 'nominalJumlahKwajibanIDR':'Oustanding/Baki Debet', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #ljkKet	jenisFasilitasKet	nominalJumlahKwajibanIDR	jumlahHariTunggakan	kualitasKet	tahunBulan24
                        #Kreditur/Pelapor	Jenis Fasilitas	Oustanding/Baki Debet	Hari Keterlambatan	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_4.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_4 = active_facility_4.reset_index(names='No')
                        active_facility_4['No'] = active_facility_4.index+1
                        #print(active_facility_4)
                        table_data_af_4 = active_facility_4.to_html(classes="table table-striped", index=False)

                        closed_fLain = merged_fLain[merged_fLain['kodeKondisi']=='02']
                        closed_facility_4 = closed_fLain[['namaDebitur','noIdentitas','tanggalLahir','alamat', 'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR','jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','noIdentitas':'Nomor Identitas','tanggalLahir':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisFasilitasKet':'Jenis Fasilitas', 'nominalJumlahKwajibanIDR':'Oustanding/Baki Debet', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_4 = closed_facility_4.reset_index(names='No')
                        closed_facility_4['No'] = closed_facility_4.index+1
                        table_data_cf_4 = closed_facility_4.to_html(classes="table table-striped", index=False)

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

                    del json_perusahaan['dataPokokDebitur']
                    del json_perusahaan['parameterPencarian']
                    del json_perusahaan['fasilitas']
                    del json_perusahaan['ringkasanFasilitas']
                    del json_perusahaan['kelompokPengurusPemilik']

                    
                    uploaded_data_2 = pd.DataFrame(json_perusahaan, index=[0])
                    table_data_2 = uploaded_data_2.to_html(classes="table table-striped", index=False)

                    nomor_laporan = uploaded_data_2['nomorLaporan'].to_string(index=False)

                    uploaded_data_3 = pd.DataFrame(json_paramPencarian, index=[0])
                    table_data_3 = uploaded_data_3.to_html(classes="table table-striped", index=False)

                    uploaded_data_4 = pd.DataFrame(json_dpdebitur)
                    table_data_4 = uploaded_data_4.to_html(classes="table table-striped", index=False)

                    uploaded_data_5 = pd.DataFrame(json_rFasilitas, index=[0])
                    table_data_5 = uploaded_data_5.to_html(classes="table table-striped", index=False)

                    uploaded_data_6 = pd.DataFrame(json_fKreditPembiayan)
                    uploaded_data_6.drop(columns=[col for col in columns_to_remove if col in uploaded_data_6.columns], inplace=True)
                    table_data_6 = uploaded_data_6.to_html(classes="table table-striped", index=False)

                    if len(uploaded_data_6)>0:
                        merged_fKP = uploaded_data_6.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fKP = merged_fKP[merged_fKP['kondisi']=='00']
                        active_facility_1 = active_fKP[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisKreditPembiayaanKet', 'jenisPenggunaanKet', 'plafon', 'bakiDebet', 'tunggakanPokok', 'tunggakanBunga', 'denda', 'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisKreditPembiayaanKet':'Jenis Kredit/Pembiayaan', 'jenisPenggunaanKet':'Jenis Penggunaan', 'plafon':'Plafon', 'bakiDebet':'Oustanding/Baki Debet', 'tunggakanPokok':'Tunggakan Pokok', 'tunggakanBunga':'Tunggakan Bunga', 'denda':'Denda', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #namaDebitur		npwp	tglAktaPendirian	alamat	ljkKet	jenisKreditPembiayaanKet	jenisPenggunaanKet	plafon	bakiDebet	tunggakanPokok	tunggakanBunga	denda	jumlahHariTunggakan	kualitasKet	tahun	bulan
                        #Nama Debitur/Calon Debitur	Nomor Laporan	Nomor Identitas	Tanggal Lahir/Pendirian	Alamat	Kreditur/Pelapor	Jenis Kredit/Pembiayaan 	Jenis Penggunaan 	Plafon	Oustanding/Baki Debet	Tunggakan Pokok	Tunggakan Bunga	Denda	Hari Keterlambatan	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_1.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_1 = active_facility_1.reset_index(names='No')
                        active_facility_1['No'] = active_facility_1.index+1
                        table_data_af_1 = active_facility_1.to_html(classes="table table-striped", index=False)

                        closed_fKP = merged_fKP[merged_fKP['kondisi']=='02']
                        closed_facility_1 = closed_fKP[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisKreditPembiayaanKet', 'jenisPenggunaanKet', 'plafon', 'bakiDebet', 'tunggakanPokok', 'tunggakanBunga', 'denda', 'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisKreditPembiayaanKet':'Jenis Kredit/Pembiayaan', 'jenisPenggunaanKet':'Jenis Penggunaan', 'plafon':'Plafon', 'bakiDebet':'Oustanding/Baki Debet', 'tunggakanPokok':'Tunggakan Pokok', 'tunggakanBunga':'Tunggakan Bunga', 'denda':'Denda', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_1 = closed_facility_1.reset_index(names='No')
                        closed_facility_1['No'] = closed_facility_1.index+1
                        table_data_cf_1 = closed_facility_1.to_html(classes="table table-striped", index=False)

                    uploaded_data_7 = pd.DataFrame(json_fLC)
                    uploaded_data_7.drop(columns=[col for col in columns_to_remove if col in uploaded_data_7.columns], inplace=True)
                    table_data_7 = uploaded_data_7.to_html(classes="table table-striped", index=False)
                    
                    if len(uploaded_data_7)>0:
                        merged_fLC = uploaded_data_7.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fLC = merged_fLC[merged_fLC['kondisi']=='00']
                        active_facility_2 = active_fLC[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisLcKet', 'tujuanLcKet', 'plafon', 'nominalLc', 'tanggalWanPrestasi', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisLcKet':'Jenis L/C', 'tujuanLcKet':'Tujuan L/C', 'plafon':'Plafon', 'nominalLc':'Oustanding/Baki Debet', 'tanggalWanPrestasi':'Tanggal Wan prestasi', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #ljkKet	jenisLcKet	tujuanLcKet	plafon	nominalLc	tanggalWanPrestasi	kualitasKet	tahunBulan24
                        #Kreditur/Pelapor	Jenis L/C	Tujuan L/C	Plafon	Oustanding/Baki Debet	Tanggal Wan prestasi	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_2.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_2 = active_facility_2.reset_index(names='No')
                        active_facility_2['No'] = active_facility_2.index+1
                        table_data_af_2 = active_facility_2.to_html(classes="table table-striped", index=False)

                        closed_fLC = merged_fLC[merged_fLC['kondisi']=='02']
                        closed_facility_2= closed_fLC[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisLcKet', 'tujuanLcKet', 'plafon', 'nominalLc', 'tanggalWanPrestasi', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisLcKet':'Jenis L/C', 'tujuanLcKet':'Tujuan L/C', 'plafon':'Plafon', 'nominalLc':'Oustanding/Baki Debet', 'tanggalWanPrestasi':'Tanggal Wan prestasi', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_2 = closed_facility_2.reset_index(names='No')
                        closed_facility_2['No'] = closed_facility_2.index+1
                        table_data_cf_2 = closed_facility_2.to_html(classes="table table-striped", index=False)

                    uploaded_data_8 = pd.DataFrame(json_fGaransi)
                    uploaded_data_8.drop(columns=[col for col in columns_to_remove if col in uploaded_data_8.columns], inplace=True)
                    table_data_8 = uploaded_data_8.to_html(classes="table table-striped", index=False)
                    
                    if len(uploaded_data_8)>0:
                        merged_fGar = uploaded_data_8.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fGar = merged_fGar[merged_fGar['kodeKondisi']=='00']
                        active_facility_3 = active_fGar[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisGaransiKet', 'tujuanGaransiKet', 'plafon', 'nominalBg', 'tanggalWanPrestasi', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisGaransiKet':'Jenis Garansi', 'tujuanGaransiKet':'Tujuan Garansi', 'plafon':'Plafon', 'nominalBg':'Oustanding/Baki Debet', 'tanggalWanPrestasi':'Tanggal Wan prestasi', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #ljkKet	jenisGaransiKet	tujuanGaransiKet	plafon	nominalBg	tanggalWanPrestasi	kualitasKet	tahunBulan24
                        #Kreditur/Pelapor	Jenis Garansi	Tujuan Garansi	Plafon	Oustanding/Baki Debet	Tanggal Wan prestasi	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_3.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_3 = active_facility_3.reset_index(names='No')
                        active_facility_3['No'] = active_facility_3.index+1
                        table_data_af_3 = active_facility_3.to_html(classes="table table-striped", index=False)

                        closed_fGar = merged_fGar[merged_fGar['kodeKondisi']=='02']
                        closed_facility_3= closed_fGar[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisGaransiKet', 'tujuanGaransiKet', 'plafon', 'nominalBg', 'tanggalWanPrestasi', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisGaransiKet':'Jenis Garansi', 'tujuanGaransiKet':'Tujuan Garansi', 'plafon':'Plafon', 'nominalBg':'Oustanding/Baki Debet', 'tanggalWanPrestasi':'Tanggal Wan prestasi', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_3 = closed_facility_3.reset_index(names='No')
                        closed_facility_3['No'] = closed_facility_3.index+1
                        table_data_cf_3 = closed_facility_3.to_html(classes="table table-striped", index=False)

                    uploaded_data_9 = pd.DataFrame(json_fFasilitasLain)
                    uploaded_data_9.drop(columns=[col for col in columns_to_remove if col in uploaded_data_9.columns], inplace=True)
                    table_data_9 = uploaded_data_9.to_html(classes="table table-striped", index=False)
                    
                    if len(uploaded_data_9)>0:
                        merged_fLain = uploaded_data_9.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fLain = merged_fLain[merged_fLain['kodeKondisi']=='00']
                        active_facility_4 = active_fLain[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR','jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisFasilitasKet':'Jenis Fasilitas', 'nominalJumlahKwajibanIDR':'Oustanding/Baki Debet', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #ljkKet	jenisFasilitasKet	nominalJumlahKwajibanIDR	jumlahHariTunggakan	kualitasKet	tahunBulan24
                        #Kreditur/Pelapor	Jenis Fasilitas	Oustanding/Baki Debet	Hari Keterlambatan	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_4.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_4 = active_facility_4.reset_index(names='No')
                        active_facility_4['No'] = active_facility_4.index+1
                        table_data_af_4 = active_facility_4.to_html(classes="table table-striped", index=False)

                        closed_fLain = merged_fLain[merged_fLain['kodeKondisi']=='02']
                        closed_facility_4= closed_fLain[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisFasilitasKet', 'nominalJumlahKwajibanIDR','jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisFasilitasKet':'Jenis Fasilitas', 'nominalJumlahKwajibanIDR':'Oustanding/Baki Debet', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_4 = closed_facility_4.reset_index(names='No')
                        closed_facility_4['No'] = closed_facility_4.index+1
                        table_data_cf_4 = closed_facility_4.to_html(classes="table table-striped", index=False)

                    uploaded_data_10= pd.DataFrame(json_fSuratBerharga)
                    uploaded_data_10.drop(columns=[col for col in columns_to_remove if col in uploaded_data_10.columns], inplace=True)
                    table_data_10 = uploaded_data_10.to_html(classes="table table-striped", index=False)

                    if len(uploaded_data_10)>0:
                        merged_fSB = uploaded_data_10.merge(uploaded_data_4, left_on='ljk', right_on='pelapor', how='left')
                        active_fSB = merged_fSB[merged_fSB['kondisi']=='00']
                        active_facility_5 = active_fSB[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisSuratBerharga', 'nilaiPasar', 'nilaiPerolehan', 'nominalSb', 'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisSuratBerharga':'Jenis Surat Berharga', 'nilaiPasar':'Nilai Pasar', 'nilaiPerolehan':'Nilai Perolehan', 'nominalSb':'Oustanding/Baki Debet', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        #ljkKet	jenisSuratBerharga	nilaiPasar	nilaiPerolehan	nominalSb	jumlahHariTunggakan	kualitasKet	tahunBulan24
                        #Kreditur/Pelapor	Jenis Surat Berharga	Nilai Pasar	Nilai Perolehan	Oustanding/Baki Debet	Hari Keterlambatan	Kolektibilitas Saat ini	Periode PelaporanTerakhir
                        active_facility_5.insert(1, 'Nomor Laporan', nomor_laporan, allow_duplicates=False)
                        active_facility_5 = active_facility_5.reset_index(names='No')
                        active_facility_5['No'] = active_facility_5.index+1
                        table_data_af_5 = active_facility_5.to_html(classes="table table-striped", index=False)

                        closed_fSB = merged_fSB[merged_fSB['kondisi']=='02']
                        closed_facility_5= closed_fSB[['namaDebitur','npwp','tglAktaPendirian','alamat', 'ljkKet', 'jenisSuratBerharga', 'nilaiPasar', 'nilaiPerolehan', 'nominalSb', 'jumlahHariTunggakan', 'kualitas', 'kualitasKet', 'tahunBulan24']].rename(columns={'namaDebitur': 'Nama Debitur/Calon Debitur','npwp':'Nomor Identitas','tglAktaPendirian':'Tanggal Lahir/Pendirian','alamat':'Alamat', 'ljkKet':'Kreditur/Pelapor', 'jenisSuratBerharga':'Jenis Surat Berharga', 'nilaiPasar':'Nilai Pasar', 'nilaiPerolehan':'Nilai Perolehan', 'nominalSb':'Oustanding/Baki Debet', 'jumlahHariTunggakan':'Hari Keterlambatan', 'kualitas':'Kode Kolektibilitas Saat ini', 'kualitasKet':'Kolektibilitas Saat ini', 'tahunBulan24':'Periode Pelaporan Terakhir'})
                        closed_facility_5 = closed_facility_5.reset_index(names='No')
                        closed_facility_5['No'] = closed_facility_5.index+1
                        table_data_cf_5 = closed_facility_5.to_html(classes="table table-striped", index=False)

                    df_kPengurusPemilik = pd.DataFrame(json_kPengurusPemilik) 
                    data_temp = {'kodeLJK': ['1', '2', '3'], 'namaLJK': ['A', 'B', 'C'], 'pengurusPemilik': ['X', 'Y', 'Z']}
                    df_temp = pd.DataFrame(data_temp)
                    df_expanded = df_temp.head(0)

                    for row in df_kPengurusPemilik.itertuples(index=False):
                        for x in row.pengurusPemilik:
                            df_expanded.loc[len(df_expanded)] = [row.kodeLJK, row.namaLJK, x]
                
                    df_expanded = df_expanded.join(pd.json_normalize(df_expanded.pop('pengurusPemilik')))

                    uploaded_data_11 = df_expanded #pd.DataFrame(json_kPengurusPemilik, index=[0])
                    table_data_11 = uploaded_data_11.to_html(classes="table table-striped", index=False)

                # Convert JSON to DataFrame and add flag column

                # Generate HTML table
                #table_data = uploaded_data.to_html(classes="table table-striped", index=False)
                #table_data_2 = uploaded_data_2.to_html(classes="table table-striped", index=False)
                #table_data_2 = uploaded_data_2.to_html(classes="table table-striped", index=False)
            except Exception as e:
                flash(f"Error processing file: {e}")
        else:
            flash("Please upload a valid JSON file.")

    return render_template(
        'upload.html',
        table_data=table_data,
        table_data_2=table_data_2,
        table_data_3=table_data_3,
        table_data_4=table_data_4,
        table_data_5=table_data_5,
        table_data_6=table_data_6,
        table_data_7=table_data_7,
        table_data_8=table_data_8,
        table_data_9=table_data_9,
        table_data_10=table_data_10,
        table_data_11=table_data_11, 
        flags=FLAGS, 
        table_data_af_1=table_data_af_1, 
        table_data_af_2=table_data_af_2, 
        table_data_af_3=table_data_af_3, 
        table_data_af_4=table_data_af_4, 
        table_data_af_5=table_data_af_5, 
        table_data_cf_1=table_data_cf_1, 
        table_data_cf_2=table_data_cf_2, 
        table_data_cf_3=table_data_cf_3, 
        table_data_cf_4=table_data_cf_4, 
        table_data_cf_5=table_data_cf_5,
        role_access=role_access
    )

# Download Route
@app.route('/download')
def download_file():
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

    if uploaded_data is None:
        flash("No file data to download.")
        return redirect(url_for('upload_file'))

    # Save DataFrame to Excel file
    output_file = "D:\\SMI_SlikReader\\.venv\\output.xlsx"
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
    app.run(host="0.0.0.0", port=5000)
