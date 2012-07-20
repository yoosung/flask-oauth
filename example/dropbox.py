# -*- coding: utf-8 -*-

from flask import Flask
from flask import session
from flask import url_for
from flask import redirect
from flaskext.oauth import OAuth


# these values are from https://www.dropbox.com/developers/apps
DROPBOX_APP_KEY = '<YOUR-APP-KEY>'
DROPBOX_APP_SECRET = '<YOUR-APP-SECRET>'


app = Flask(__name__)
app.debug = True
app.secret_key = 'secret-key-of-this-flask-app'

oauth = OAuth()
dropbox = oauth.remote_app('dropbox',
                           base_url='https://api.dropbox.com/1/',
                           request_token_url='https://api.dropbox.com/1/oauth/request_token',
                           authorize_url='https://www.dropbox.com/1/oauth/authorize',
                           access_token_url='https://api.dropbox.com/1/oauth/access_token',
                           access_token_method='POST',
                           consumer_key=DROPBOX_APP_KEY,
                           consumer_secret=DROPBOX_APP_SECRET)


@app.route('/')
def index():
    token_and_secret = session.get('token_and_secret')
    if token_and_secret is None:
        return redirect(url_for('login'))

    app.logger.debug('dropbox_uid: %s', session.get('dropbox_uid'))
    app.logger.debug('token_and_secret: %s', token_and_secret)

    resp = dropbox.get('account/info')
    app.logger.debug('GET account info: %s', resp.status)
    if resp.status == 200:
        return ('<html><body>'
                '<dl>'+
                ''.join('<dt>%s</dt><dd>%s</dd>' % (k, v)
                        for k, v in resp.data.items())+
                '</dl>'
                '</body></html>')
    elif resp.status == 401:
        session.pop('token_and_secret')
        return redirect(url_for('login'))
    return '%s %s' % (resp.status, resp.raw_data)


@app.route('/login')
def login():
    callback=url_for('authorized', _external=True)
    return dropbox.authorize(callback=callback,
                             params={'oauth_callback': callback,
                                     'locale': 'en'})


@app.route('/authorized')
@dropbox.authorized_handler
def authorized(resp):
    app.logger.debug('response: %s', resp)
    token_and_secret = resp['oauth_token'], resp['oauth_token_secret']
    session['token_and_secret'] = token_and_secret
    session['dropbox_uid'] = resp['uid']
    return redirect(url_for('index'))


@dropbox.tokengetter
def get_access_token():
    app.logger.debug('get_access_token: session=%s', session)
    return session.get('token_and_secret')


def main():
    app.run()


if __name__ == '__main__':
    main()
