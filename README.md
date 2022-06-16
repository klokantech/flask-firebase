# Flask-Firebase

Google Firebase integration for Flask. At this moment,
only the authentication subsystem is supported.

The extension works in two modes: development and production.
In development, there is no communication with the Firebase
system, accounts sign-in with a simple email form. The mode
depends on the `Flask.debug` variable.

## Configuration

- `FIREBASE_API_KEY`: The API key. Get this from Firebase -> Project settings -> web api key
- `FIREBASE_PROJECT_ID`: The project identifier, eg. `foobar`. Project settings -> Project ID
- `FIREBASE_AUTH_SIGN_IN_OPTIONS`: Comma-separated list of enabled providers.

## Providers

- `email`
- `facebook`
- `github`
- `google`
- `twitter`

## Working example

To get the example below working:

- ensure you have sqlite installed
- pip install the following packages into your virtualenv: `flask`, `requests`, `flask_login`, `flask_sqlalchemy` and `pyjwt`
- run the server with `export FLASK_DEBUG=1 && venv/bin/flask run --with-threads --cert adhoc` (<-- needs SSL as the social login provider would choke otherwise)
- allow self-signed certificate on localhost: in chrome go to chrome://flags/#allow-insecure-localhost and enable the setting
- replace all REPLACE_ME in the code below

```python
from flask import Flask, request, redirect
from flask_firebase import FirebaseAuth
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.debug = False # to disable local testing
app.config['FIREBASE_API_KEY'] = 'REPLACE_ME'
app.config['FIREBASE_PROJECT_ID'] = 'REPLACE_ME'
app.config['FIREBASE_AUTH_SIGN_IN_OPTIONS'] = 'google,facebook' # <-- coma separated list, see Providers above
app.config['SECRET_KEY'] = 'REPLACE_ME' # <-- random string
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/firebase_users.db'

db = SQLAlchemy(app)
auth = FirebaseAuth(app)
login_manager = LoginManager(app)

app.register_blueprint(auth.blueprint, url_prefix='/auth')


class Account(UserMixin, db.Model):

    __tablename__ = 'accounts'

    account_id = db.Column(db.Integer)
    firebase_user_id = db.Column(db.Text, unique=True, primary_key=True)
    email = db.Column(db.Text, unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    name = db.Column(db.Text)
    photo_url = db.Column(db.Text)

    def __repr__(self):
        return str(dict(firebase_user_id=self.firebase_user_id, email=self.email, name=self.name))


db.create_all() # <-- don't use this in production! This creates the account table in your sqlite
db.session.commit()

@auth.production_loader
def production_sign_in(token):
    account = Account.query.filter_by(firebase_user_id=token['sub']).one_or_none()
    if account is None:
        account = Account(firebase_user_id=token['sub'])
        db.session.add(account)
    account.email = token['email']
    account.email_verified = token['email_verified']
    account.name = token.get('name')
    account.photo_url = token.get('picture')
    db.session.flush()
    login_user(account)
    db.session.commit()


@auth.development_loader
def development_sign_in(email):
    login_user(Account.query.filter_by(email=email).one())

@auth.unloader
def sign_out():
    logout_user()

@login_manager.user_loader
def load_user(account_id):
    return Account.query.get(account_id)

@login_manager.unauthorized_handler
def authentication_required():
    return redirect(auth.url_for('widget', mode='select', next=request.url))

@app.route("/")
@login_required
def index():
    return f"<p>Hello, {current_user.name}!</p>"
```
