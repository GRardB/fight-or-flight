import os
import dataset
import json
import random

from flask import Flask, redirect, request, session, render_template
from requests_oauthlib import OAuth2Session
from requests_oauthlib.compliance_fixes import facebook_compliance_fix

app = Flask(__name__)
app.secret_key = 'rugeiruneornero'

FACEBOOK_AUTH_BASE_URL = 'https://www.facebook.com/dialog/oauth'
FACEBOOK_TOKEN_URL = 'https://graph.facebook.com/oauth/access_token'
FACEBOOK_REDIRECT_URI = 'https://28e229b9.ngrok.com/oauth'
FACEBOOK_CLIENT_ID = os.environ['FACEBOOK_CLIENT_ID']
FACEBOOK_CLIENT_SECRET = os.environ['FACEBOOK_CLIENT_SECRET']

def get_facebook(session=None):
    if session:
        facebook = OAuth2Session(FACEBOOK_CLIENT_ID, token=session['oauth_token'])
    else:
        facebook = OAuth2Session(
            FACEBOOK_CLIENT_ID,
            redirect_uri=FACEBOOK_REDIRECT_URI,
            scope=['user_photos']
        )
    return facebook_compliance_fix(facebook)

facebook = get_facebook()

db = dataset.connect('sqlite:///db.db')
users = db['users']
matches = db['matches']
messages = db['messages']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    if 'oauth_token' in session:
        return redirect('/oauth_success')
    authorization_url, state = facebook.authorization_url(FACEBOOK_AUTH_BASE_URL)
    return redirect(authorization_url)

@app.route('/logout')
def logout():
    try: session.pop('oauth_token')
    except: pass

    try: session.pop('user_data')
    except: pass

    return redirect('/')

@app.route('/oauth')
def oauth():
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    token = facebook.fetch_token(
        FACEBOOK_TOKEN_URL,
        client_secret=FACEBOOK_CLIENT_SECRET,
        authorization_response=request.url
    )
    session['oauth_token'] = token
    return redirect('/oauth_success')

@app.route('/oauth_success')
def oauth_success():
    facebook = get_facebook(session)
    user_data = json.loads(facebook.get('https://graph.facebook.com/me').content)
    print user_data

    if len(users) == 0 or not users.find_one(id=user_data['id']):
        session['user_data'] = {
            'id': user_data['id'],
            'name': user_data['name'],
            'gender': user_data['gender']
        }
        return redirect('/setup')
    else:
        user = users.find_one(id=user_data['id'])
        session['user_data'] = {
            'id': user['id'],
            'name': user['name'],
            'gender': user['gender']
        }
        print user
        return redirect('/match')

@app.route('/setup', methods=['GET'])
def setup_get():
    if 'user_data' not in session or 'oauth_token' not in session:
        return redirect('/')

    facebook = get_facebook(session)
    response = json.loads(facebook.get('https://graph.facebook.com/me/photos').content)
    next_page = response['paging']['next']
    previous_page = response['paging']['previous']

    photos = [
        photo['source']
        for photo
        in response['data']
    ]

    return render_template(
        'setup.html',
        next_page=next_page,
        previous_page=previous_page,
        photos=photos
    )

@app.route('/setup', methods=['POST'])
def setup_post():
    address = request.form['address']
    photos = request.values.getlist('photos')
    user_data = session['user_data']
    users.insert({
        'id': user_data['id'],
        'name': user_data['name'],
        'gender': user_data['gender'],
        'address': address,
        'pic_1': photos[0],
        'pic_2': None if len(photos) < 2 else photos[1],
        'pic_3': None if len(photos) < 3 else photos[2]
    })

    return redirect('/match')

@app.route('/match')
def match():
    if 'user_data' not in session or 'oauth_token' not in session:
        return redirect('/')
    user_data = session['user_data']
    user = users.find_one(id=user_data['id'])
    if not user:
        return redirect('/setup')

    return render_template('match.html')

@app.route('/get_user')
def get_user():
    if 'user_data' not in session or 'oauth_token' not in session:
        return redirect('/')
    user_data = session['user_data']
    user = users.find_one(id=user_data['id'])
    if not user:
        return redirect('/setup')

    matched_users = matches.find(
        user_1=user_data['id']
    )

    if 'matches' not in db.tables:
        return json.dumps({})

    user_ids = map(str, [user_data['id']] + [match['user_2'] for match in matched_users])
    user_ids_str = '(%s)' % ','.join(user_ids)

    all_users = [u for u in db.query('SELECT * FROM users WHERE id not in %s' % user_ids_str)]

    if not all_users:
        return json.dumps('')

    random_user = random.choice(all_users)

    random_user['id'] = str(random_user['id'])

    return json.dumps(random_user)

@app.route('/flee', methods=['POST'])
def flee():
    if 'user_data' not in session or 'oauth_token' not in session:
        return redirect('/')
    user_data = session['user_data']
    user = users.find_one(id=user_data['id'])
    if not user:
        return redirect('/setup')

    match = matches.insert({
        'user_1' : user_data['id'],
        'user_2' : request.form['id'],
        'fight' : False
    })

    return json.dumps(match)

@app.route('/fight', methods=['POST'])
def fight():
    if 'user_data' not in session or 'oauth_token' not in session:
        return redirect('/')
    user_data = session['user_data']
    user = users.find_one(id=user_data['id'])
    if not user:
        return redirect('/setup')

    match = matches.insert({
        'user_1' : user_data['id'],
        'user_2' : request.form['id'],
        'fight' : True
    })

    return json.dumps(match)

@app.route('/matches')
def matched_users():
    if 'user_data' not in session or 'oauth_token' not in session:
        return redirect('/')
    user_data = session['user_data']
    user = users.find_one(id=user_data['id'])
    if not user:
        return redirect('/setup')

    matched_users = matches.find(
        user_1=user_data['id'],
        fight=True
    )

    matched_users_reversed = matches.find(
        user_2=user_data['id'],
        fight=True
    )

    matched_users_query = '''
        SELECT *
        FROM matches m1
        WHERE m1.user_1 = %s
        AND m1.fight = 1
        AND EXISTS (
            SELECT *
            FROM matches m2
            WHERE m2.user_2 = m1.user_1
            AND m2.fight = 1
        )
    '''

    pairs = [p for p in db.query(matched_users_query % user_data['id'])]

    opponent_ids = ','.join([i['user_2'] for i in pairs])

    opponents = [m for m in db.query('SELECT * FROM users WHERE id IN (%s)' % opponent_ids)]

    return render_template('matches.html', matches=opponents)

@app.route('/matches/<opponent_id>')
def message(opponent_id):
    if 'user_data' not in session or 'oauth_token' not in session:
        return redirect('/')
    user_data = session['user_data']
    user = users.find_one(id=user_data['id'])
    if not user:
        return redirect('/setup')

    opponent = users.find_one(id=opponent_id)

    return render_template('confront.html', user=user_data, opponent=opponent)

@app.route('/messages/<opponent_id>')
def get_messages(opponent_id):
    user_id = session['user_data']['id']


    if len(messages) == 0:
        return json.dumps([])

    msgs = [
        msg
        for msg
        in db.query('''
                    SELECT *
                    FROM messages
                    WHERE (user_1 = %s AND user_2 = %s)
                    OR (user_1 = %s AND user_2 = %s)''' % (user_id, opponent_id, opponent_id, user_id)
                    )
    ]

    return json.dumps(msgs)


@app.route('/message', methods=['POST'])
def send_message():
    user_data = session['user_data']
    opponent_id = request.form['opponent_id']
    opponent_name = request.form['opponent_name']
    message = request.form['message']

    message = db['messages'].insert({
        'user_1': user_data['id'],
        'user_2': opponent_id,
        'user_1_name': user_data['name'],
        'user_2_name': opponent_name,
        'message': message
    })

    return json.dumps(message)

    
@app.route('/policy')
def policy():
    return render_template('policy.html')
    
if __name__ == '__main__':
    app.run(debug=True)
