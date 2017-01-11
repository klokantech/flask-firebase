# Flask-Firebase

Google Firebase integration for Flask. At this moment,
only the authentication subsystem is supported.

The extension works in two modes: development and production.
In development, there is no communication with the Firebase
system, accounts sign-in with a simple email form. The mode
depends on the `Flask.debug` variable.

## Configuration

- `FIREBASE_API_KEY`: The API key.
- `FIREBASE_PROJECT_ID`: The project identifier, eg. `foobar`.
- `FIREBASE_AUTH_SIGN_IN_OPTIONS`: Comma-separated list of enabled providers.

## Providers

- `email`
- `facebook`
- `github`
- `google`
- `twitter`

## Sample code

```python
from flask import Flask, request
from flask_firebase import FirebaseAuth
from flask_login import LoginManager, UserMixin, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config.from_object(...)

db = SQLAlchemy(app)
auth = FirebaseAuth(app)
login_manager = LoginManager(app)

app.register_blueprint(auth.blueprint, url_prefix='/auth')


class Account(UserMixin, db.Model):

    __tablename__ = 'accounts'

    account_id = db.Column(db.Integer, primary_key=True)
    firebase_user_id = db.Column(db.Text, unique=True)
    email = db.Column(db.Text, unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    name = db.Column(db.Text)
    photo_url = db.Column(db.Text)


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


@app.development_loader
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
    return auth.url_for('widget', mode='select', next=request.url)
```
