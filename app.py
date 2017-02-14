# coding: utf-8

from datetime import datetime, timedelta
from flask import Flask
from flask import session, request, flash, url_for
from flask import render_template, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import gen_salt
from flask_oauthlib.provider import OAuth2Provider

app = Flask(__name__, template_folder='templates')
app.debug = True
app.secret_key = 'secret'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db = SQLAlchemy(app)
oauth = OAuth2Provider(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(40), nullable=False)


class Client(db.Model):
    client_name = db.Column(db.String(20), nullable=False)
    client_des = db.Column(db.String(40), nullable=False)

    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)

    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@app.route('/')
def home():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('home.html', user=user)


@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        if username is None or password is None or email is None:
            flash('missing user info')
            return redirect(url_for('register'))
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username,
                        password=password,
                        email=email)
            db.session.add(user)
            db.session.commit()
            flash('register user %s successfully, please login' % username)
            return redirect(url_for('login'))
        else:
            flash('user %s have been already registered, please try another username' % username)
            return redirect(url_for('register'))
    return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username is None or password is None:
            flash('missing user info')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username, password=password).first()
        if not user:
            flash('username or correct incorrect, please try again')
            return redirect(url_for('login'))
        else:
            session['id'] = user.id
            return redirect('/')
    return render_template('login.html')


@app.route('/logout')
def logout():
    try:
        session.pop('id')
    except KeyError:
        pass
    finally:
        return redirect(url_for('login'))


@app.route('/client')
def client():
    user = current_user()
    if not user:
        return redirect('/')
    clients = Client.query.filter_by(user_id=user.id).all()
    return render_template('client.html', clients=clients)


@app.route('/register_client', methods=('GET', 'POST'))
def register_client():
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'POST':
        client_name = request.form.get('client_name')
        client_des = request.form.get('client_des')
        callback_uri = request.form.get('callback_uri')
        if client_name is None or client_des is None or callback_uri is None:
            flash("missing required client info")
            return redirect(url_for('register_client'))
        if request.method == 'POST':
            item = Client(
                client_name=client_name,
                client_des=client_des,
                client_id=gen_salt(40),
                client_secret=gen_salt(50),
                _redirect_uris=' '.join([
                    callback_uri
                ]),
                _default_scopes='email',
                user_id=user.id,
            )
            db.session.add(item)
            db.session.commit()
            flash('register client %s successfully' % client_name)
            return redirect(url_for('client'))
    return render_template('register_client.html')


@app.route('/authorized_app')
def authorized_app():
    user = current_user()
    if not user:
        return redirect('/')
    applications = Token.query.filter_by(user_id=user.id).all()
    clients = {}
    for _app in applications:
        _client = Client.query.filter_by(client_id=_app.client_id).first()
        clients[_app.client_id] = _client.client_name
    return render_template('authorized_app.html', apps=applications, clients=clients)


@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok


@app.route('/oauth/token', methods=['GET', 'POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/api/me')
@oauth.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username, email=user.email)


if __name__ == '__main__':
    db.create_all()
    app.run()
