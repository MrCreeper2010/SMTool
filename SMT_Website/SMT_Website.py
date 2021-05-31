from flask import Flask, render_template
from flask import request
import json, time

app = Flask(__name__)

@app.route('/')
#def index():
    #return render_template('index.html')
def hello_world():
    text = str(request.args.get('input'))
    text2 = str(request.args.get('fringuellos'))
    char_c = len(text)

    data_set = {'input':text, 'timestamp':time.time(), 'char_c': char_c, 'fringuellos':text2}
    json_dump = json.dumps(data_set)
    return json_dump