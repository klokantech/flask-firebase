import jwt
import requests

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from flask import Blueprint, abort, current_app, redirect, request, \
    render_template, url_for
from threading import Lock
from time import monotonic
from urllib.parse import urlparse
from werkzeug.http import parse_cache_control_header


blueprint = Blueprint('firebase_auth', __name__, template_folder='templates')


@blueprint.route('/widget', methods={'GET', 'POST'})
def widget():
    return current_app.extensions['firebase_auth'].widget()


@blueprint.route('/sign-in', methods={'POST'})
def sign_in():
    return current_app.extensions['firebase_auth'].sign_in()


@blueprint.route('/sign-out')
def sign_out():
    return current_app.extensions['firebase_auth'].sign_out()


class FirebaseAuth:

    KEYCHAIN_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'  # noqa

    PROVIDER_CLASSES = {
        'email': 'EmailAuthProvider',
        'facebook': 'FacebookAuthProvider',
        'github': 'GithubAuthProvider',
        'google': 'GoogleAuthProvider',
        'twitter': 'TwitterAuthProvider',
    }

    def __init__(self, app=None, **kwargs):
        self.api_key = None
        self.project_id = None
        self.provider_ids = None
        self.server_name = None
        self.development = None
        self.production_load_callback = None
        self.development_load_callback = None
        self.unload_callback = None
        self.blueprint = blueprint
        self.keys = {}
        self.max_age = 0
        self.cached_at = 0
        self.lock = Lock()
        if app is not None:
            self.init_app(app, **kwargs)

    def init_app(self, app):
        app.extensions['firebase_auth'] = self
        self.api_key = app.config['FIREBASE_API_KEY']
        self.project_id = app.config['FIREBASE_PROJECT_ID']
        self.server_name = app.config['SERVER_NAME']
        self.development = app.config.get('FIREBASE_DEVELOPMENT', False)
        if self.development:
            return
        provider_ids = []
        for name in app.config['FIREBASE_AUTH_SIGN_IN_OPTIONS'].split(','):
            class_name = self.PROVIDER_CLASSES[name.strip()]
            provider_id = 'firebase.auth.{}.PROVIDER_ID'.format(class_name)
            provider_ids.append(provider_id)
        self.provider_ids = ','.join(provider_ids)

    def production_loader(self, callback):
        self.production_load_callback = callback
        return callback

    def development_loader(self, callback):
        self.development_load_callback = callback
        return callback

    def unloader(self, callback):
        self.unload_callback = callback
        return callback

    def url_for(self, endpoint, **values):
        full_endpoint = 'firebase_auth.{}'.format(endpoint)
        if self.development:
            return url_for(full_endpoint, **values)
        else:
            return url_for(
                full_endpoint,
                _external=True,
                _scheme='https',
                **values)

    def widget(self):
        next_ = self.verify_redirection()
        if self.development:
            if request.method == 'POST':
                self.development_load_callback(request.form['email'])
                return redirect(next_)
            else:
                return render_template('firebase_auth/development_widget.html')
        else:
            return render_template(
                'firebase_auth/production_widget.html',
                firebase_auth=self)

    def sign_in(self):
        assert not self.development
        header = jwt.get_unverified_header(request.data)
        with self.lock:
            self.refresh_keys()
            key = self.keys[header['kid']]
        token = jwt.decode(
            request.data,
            key=key,
            audience=self.project_id,
            algorithms=['RS256'])
        self.production_load_callback(token)
        return 'OK'

    def sign_out(self):
        self.unload_callback()
        return redirect(self.verify_redirection() or request.url_root)

    def verify_redirection(self):
        next_ = request.args.get('next')
        if not next_:
            return None
        if self.server_name:
            url = urlparse(next_)
            if not url.netloc.endswith(self.server_name):
                abort(400)
        return next_

    def refresh_keys(self):
        now = monotonic()
        age = now - self.cached_at
        if age >= self.max_age:
            response = requests.get(self.KEYCHAIN_URL)
            if response.status_code != 200:
                raise Exception
            hazmat = default_backend()
            for kid, text in response.json().items():
                certificate = load_pem_x509_certificate(
                    bytes(text, 'utf-8'),
                    hazmat)
                self.keys[kid] = certificate.public_key()
            cache_control = response.headers['Cache-Control']
            self.max_age = parse_cache_control_header(cache_control).max_age
            self.cached_at = now
