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
                debug(len(table_data))
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
                        uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                        merged_fKP = uploaded_data_6.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
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
                        uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                        merged_fLC = uploaded_data_7.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
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
                        uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                        merged_fGar = uploaded_data_8.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
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
                        uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                        merged_fLain = uploaded_data_9.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
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
                        uploaded_data_4_dedup = uploaded_data_4.drop_duplicates(subset=['pelapor'])
                        merged_fSB = uploaded_data_10.merge(uploaded_data_4_dedup, left_on='ljk', right_on='pelapor', how='left')
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
