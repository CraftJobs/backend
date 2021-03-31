from bp.blueprint import Blueprint
from util.mail import send_mail
from quart import g, request as quart_rq, jsonify, Request
from secrets import token_hex
from uuid import uuid4
from datetime import datetime, timedelta
import bcrypt
import http3
import asyncpg


register_bp = Blueprint('register', __name__)
register_debug_bp = Blueprint('register/_debug', __name__)


@register_bp.route('/send-email', methods=['POST'])
async def send_email_route():
    request: Request = quart_rq

    json = await request.get_json()
    no_send_on_no_acc = 'f' in request.args

    if 'email' not in json:
        return {'message': 'Missing email.'}

    if 'captchaToken' not in json:
        return {'message': 'Missing CAPTCHA token.'}

    email = json['email']

    if '@' not in email:
        return {'message': 'Invalid email.'}

    if await g.redis.exists('ratelimit:register:send_mail:' + email.lower()):
        return {'message': 'You can only do this once every 10 minutes.'}

    token = token_hex(32)
    device_token = token_hex(32)

    key = 'register:email_token:'
    title = 'Verify your email'
    body = 'You can finish your registration here'
    link = 'register/finish/'
    is_reset = False

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con
        if await con.fetchval(
                'SELECT COUNT(email) FROM users WHERE email = $1',
                email.lower()):
            key = 'login:password_reset:'
            title = 'Reset your password'
            body = 'You already have an account, you can reset your ' \
                   'password here:'
            link = 'login/change-password?t='
            is_reset = True

    http: http3.AsyncClient = g.http
    success = (await http.post('https://hcaptcha.com/siteverify', data={
        'response': json['captchaToken'],
        'secret': g.config['hc_secret']
    })).json()['success']

    if not success:
        return {'message': 'Invalid CAPTCHA response! Refresh and try again.'}

    if g.config['alpha']:
        key = 'alpha:invite:' + email

        if email[-4:] != '@inv':
            return {'message': 'You must use an alpha invite code'}
        elif not await g.redis.exists(key):
            return {'message': 'Invalid invite'}
        else:
            email = await g.redis.get(key)
            await g.redis.delete(key)

    await g.redis.setex(key + token, 600, email.lower())
    await g.redis.setex('register:device_token:' + device_token, 600, token)
    await g.redis.setex('ratelimit:register:send_mail:' + email.lower(), 600, 'a')

    if not (no_send_on_no_acc and not is_reset):
        send_mail(email, f'[CraftJobs] {title}',
                         f"""Dear user,
                     
Thanks for signing up for CraftJobs!
{body}
https://craftjobs.net/i/{link}{token}

If you did not request this message, you can safely ignore it.

Much Love,
- The CraftJobs Team
https://craftjobs.net
""")

    return {'message': 'Email sent. Check your inbox!',
            'deviceToken': device_token}


@register_bp.route('/check-email-token')
async def check_email_token():
    request: Request = quart_rq
    token = request.args.get('token')

    if not token:
        return {'success': False, 'message': 'Missing token parameter'}

    email = await g.redis.get('register:email_token:' + token)

    return {'success': bool(email), 'email': email.decode('utf-8')}


ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
VALID_USERNAME_CHARS = ALPHABET + ALPHABET.lower() + '0123456789_'


def no(message: str):
    return {'success': False, 'message': message}


@register_bp.route('/finish', methods=['POST'])
async def finish():
    json = await quart_rq.get_json()

    if 'emailToken' not in json:
        return no('Missing email token.')
    elif 'username' not in json:
        return no('Missing username.')
    elif 'password' not in json:
        return no('Missing password.')

    email_token = json['emailToken']
    username = json['username']
    password = json['password']
    device_token = json['deviceToken'] if 'deviceToken' in json else None

    # Validate email token and get relevant email
    email_token_key = 'register:email_token:' + email_token
    email = (await g.redis.get(email_token_key))
    if not email:
        return no('Invalid email token.')
    email: str = email.decode('utf-8')

    # Validate username
    if len(username) < 3:
        return no('Username must be at least 3 characters.')
    elif len(username) > 32:
        return no('Username must be at most 32 characters.')
    elif 'CraftJobs' in username:
        return no('Username cannot contain CraftJobs')
    else:
        for _, char in enumerate(username):
            if char not in VALID_USERNAME_CHARS:
                return no('Usernames can only contain alphanumeric ' +
                          'characters and underscores.')

    # Check if username exists
    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con

        username_lower = username.lower()

        users_with_username = await con.fetchval(
            'SELECT COUNT(username_lower) FROM users ' +
            'WHERE username_lower = $1', username_lower)
        if users_with_username > 0:
            return no('That username is already in use.')

        user_id = uuid4()

        # Insert user
        await con.execute('INSERT INTO users (id, username, ' +
                          'username_lower, password_hashed, full_name, ' +
                          'avatar_url, email) VALUES ($1, $2, $3, $4, $5, ' +
                          '$6, $7)',
                          user_id, username, username_lower,
                          bcrypt.hashpw(password.encode('utf-8'),
                                        bcrypt.gensalt()).decode('utf-8'),
                          username,
                          'https://static.craftjobs.net/default-avatar.png',
                          email.lower())

        # Remove email token
        await g.redis.delete(email_token_key)

        token = None

        # Check device token
        if device_token:
            device_token_key = 'register:device_token:' + device_token
            email_token_from_dev = await g.redis.get(device_token_key)

            if email_token_from_dev and \
                    email_token_from_dev.decode('utf-8') == email_token:
                # Valid!
                await g.redis.delete(device_token_key)
                token = token_hex(32)
                await con.execute('INSERT INTO sessions (id, token, ' +
                                  'user_id, expires_at) VALUES ($1, $2, $3, ' +
                                  '$4)', uuid4(), token, user_id,
                                  datetime.now() + timedelta(days=30))

    return {'success': True, 'token': token}


@register_debug_bp.route('/')
async def _debug():
    return jsonify(['kill ratelimits'])


@register_debug_bp.route('/kill-ratelimits')
async def _debug_kill_ratelimits():
    keys = await g.redis.keys('ratelimit:register:*')
    for key in keys:
        await g.redis.delete(key)
    return jsonify('done. killed ' + str(len(keys)))
