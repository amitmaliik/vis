from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os
from datetime import timedelta
from flask import Flask, request, render_template
from flask import Flask, jsonify, request, make_response

from flask import  flash, url_for, redirect  
import jwt 
from functools import wraps

# decorator for routes that should be accessible only by logged in users
from auth_decorator import login_required
from datetime import datetime as datetime1

# dotenv setup
from dotenv import load_dotenv

from datetime import timedelta, date
import datetime

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()


app = Flask(__name__)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]
)

# Session config
app.secret_key = 'super secret key'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

app.config['SECRET_KEY'] = 'thisisthesecretkey'


oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='921187902807-i5v5h4fp5p939dnf8ffg060i9u3skblo.apps.googleusercontent.com',
    client_secret='aWltftyw_r8czdGtpH69ZD4x',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)





def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') 
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated


app.config['UPLOAD_FOLDER'] = 'static'

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file1' not in request.files:
            return 'there is no file1 in form!'
        file1 = request.files['file1']
        path = os.path.join(app.config['UPLOAD_FOLDER'], file1.filename)
        file1.save(path)
        # return path
        return render_template("img.html", user_image = path)


        return 'ok'
    return ''' 
    <h1>  ALL url routes </h1>
    <h1> /path -- 1. Simple interface to upload images and when you click the "submit" button, it shows a new page with the name of the uploaded image. </h1>
    <h1> /login --- automtaically redirects to /protected with jwt in url args 2. Build a key based authentication system using JWT token for accessing the api functionality.</h1>
    <h1> /protected works only for only jwt token holders </h1>
    <h1> /login and  /protected  3. for throttle for api call rate, let's say 5 / min. </h1>

    <h1> /gauth Part A, build a google auth based login instead of JWT token based authorization. </h1>
    <h1> / --root home page  part 2A --3rd page to render the uploaded image in the interface. Also, implement a zoom functionality, wherein, a small window pane pops-up and shows a zoomed-in image as one hovers over the image using mouse cursor (look into the zoom-in functionality. </h1>
    
    <h1>Upload new File</h1>
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="file1">
      <input type="submit">
    </form>
    '''

@app.route('/path', methods=['GET', 'POST'])
def img_file():
    if request.method == 'POST':
        if 'file1' not in request.files:
            return 'there is no file1 in form!'
        file1 = request.files['file1']
        path = os.path.join(app.config['UPLOAD_FOLDER'], file1.filename)
        file1.save(path)
        return  path

    return '''
<h1>Upload new File</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file1">
  <input type="submit">
</form>
'''




@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'Anyone can view this!'})

@app.route('/protected')
@token_required
def protected():

    return jsonify({'message' : 'This is only available for 5/minute and (/protected) people with valid JWT tokens. See jwt is in url args, without jwt you wont be able to get into protected'})


@app.route('/login')
@limiter.limit('5 per minute')
def login():
    auth = request.authorization

    if auth and auth.password == 'secret':
        token = jwt.encode({'user' : auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=50)}, app.config['SECRET_KEY'])
        tok=token.decode('UTF-8')

        return redirect("/protected?token="f"{(tok)}")

    return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})



@app.route('/glogin')
def flogin():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)



@app.route('/gauth')
def authorize():
    # import ipdb;ipdb.set_trace()
    google = oauth.create_client('google') 
    token = google.authorize_access_token()
    print(token)  
    resp = google.get('userinfo')  
    user_info = resp.json()
    user = oauth.google.userinfo() 
    session['profile'] = user_info
    session.permanent = True      

    return user,user_info

 

  

if __name__ == '__main__':
    
    app.run(debug=True, host='0.0.0.0',port=5000)