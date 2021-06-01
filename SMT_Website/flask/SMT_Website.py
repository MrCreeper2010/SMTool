from flask import Flask, render_template, request, send_file
from urllib.parse import quote_plus
import json, time

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    response_text = str(request.args.get('response'))
    Date_scan = str(request.args.get('Date_scan'))
    Recyclebin = str(request.args.get('Recyclebin'))
    Explorer_dir = str(request.args.get('Explorer_dir'))
    scan_speed = str(request.args.get('scan_speed'))
    Alts = str(request.args.get('Alts'))
    Recording = str(request.args.get('Recording'))
    Xray = str(request.args.get('Xray'))
    Checks = str(request.args.get('Checks'))
    FilesActions = str(request.args.get('FilesActions'))
    Type = str(request.args.get('Type'))
    PST = str(request.args.get('PST'))
    DEV = str(request.args.get('DEV'))
    PCA = str(request.args.get('PCA'))
    SUS = str(request.args.get('SUS'))

    data_set = {'response':response_text, 'SUS':SUS,'PCA':PCA,'DEV':DEV,'PST':PST, 'Type':Type, 'FilesActions':FilesActions, 'Checks':Checks, 'Xray':Xray, 'Recording':Recording, 'Alts':Alts, 'Date_scan':Date_scan, 'Recyclebin':Recyclebin, 'Explorer_dir':Explorer_dir, 'scan_speed':scan_speed}
    json_dump = json.dumps(data_set, ensure_ascii=False)
    json_js = json.loads(json_dump)

    return render_template('index.html', sda=json_js, quote_s=quote_plus)
