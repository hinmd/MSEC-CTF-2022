from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
import os
import subprocess as sp
from wtforms.validators import InputRequired
from filehash import FileHash
import requests
from time import sleep


def sha256(fname):
    sha256hasher = FileHash('sha256')
    return sha256hasher.hash_file(fname)




requests.urllib3.disable_warnings()
client =  requests.session()
client.verify = False

apikey = 'ee69c5372d6b74067b84ede6ae290c847633ab04981472df23aae7f17662d5eb'
filehash = '9ccf0e46f6aadbb20f4c269d8ac85cc9b4e6ce56bf226d45eda4347a20785c88'

def get_hash_report(apikey, filehash):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {"apikey": apikey, "resource": filehash, "allinfo": True}

    # perform call
    r = client.get(url, params=params)

    if r.status_code == 429:
        print('Encountered rate-limiting. Sleeping for 45 seconds.')
        sleep(45)
        get_hash_report(apikey, filehash)

    elif r.status_code != 200:
        print('Encountered unanticipated HTTP error.')
        print(r.status_code)
        exit(1)

    elif r.status_code == 200:
        response = r.json()
        return response




app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/files'

class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")

@app.route('/', methods=['GET','POST'])
@app.route('/home', methods=['GET','POST'])
def home():
    form = UploadFileForm()
    if form.validate_on_submit():
        file = form.file.data # First grab the file
        if file.content_type == 'application/vnd.rar':
            pathFile = os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'])
            fileName = os.path.join(pathFile, secure_filename(file.filename))
            print(fileName)
            file.save(fileName) # Then save the file
            os.system('unrar x ' + fileName)
            fileNameInRar = sp.getoutput('unrar lb ' + fileName)
            try:
                hashFile = sha256(fileNameInRar)
            except:
                hashFile = ''
            if os.path.exists(fileName):
                os.remove(fileName)
            if os.path.exists(fileNameInRar):
                os.remove(fileNameInRar)
            if os.path.exists("DONTLOOKATME"):
                os.remove("DONTLOOKATME")
            result = get_hash_report(apikey, hashFile)
            return render_template('result.html', fileNameInRar = fileNameInRar, hashFile = hashFile, result = result)
        else:
            return render_template('error.html')
    return render_template('index.html', form=form)

@app.route('/hint', methods=['GET','POST'])
def hint():
    return render_template('hint.html')

if __name__ == '__main__':
    app.run(debug=False)