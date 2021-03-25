from bp.blueprint import Blueprint
from quart import g, request
from util.resp import no
from secrets import token_hex
from datetime import datetime, timedelta
from uuid import uuid4
import asyncpg
import bcrypt

login_bp = Blueprint('login', __name__)

GET_PASSWORD_AND_ID_BY_SESSION_QUERY = """
SELECT user_id as id, u.password_hashed as password_hashed 
FROM sessions 
INNER JOIN users u on sessions.user_id = u.id
WHERE token = $1"""


@login_bp.route('/', methods=['POST'])
async def root():
    json = await request.get_json()

    if 'username' not in json:
        return no('Missing username.')
    if 'password' not in json:
        return no('Missing password.')
    if 'remember' not in json:
        return no('Missing remember.')

    username = json['username']
    password = json['password']
    remember = bool(json['remember'])
    is_email = '@' in username

    column = 'email' if is_email else 'username_lower'

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con
        user = await con.fetchrow(
            'SELECT id, password_hashed FROM users ' +
            f'WHERE {column} = $1', username.lower())

        if not user:
            return no('Invalid username/email or password.')

        if not bcrypt.checkpw(password.encode('utf-8'),
                              user['password_hashed'].encode('utf-8')):
            return no('Invalid username/email or password.')

        token = token_hex(32)

        await con.execute(
            'INSERT INTO sessions (id, token, user_id, expires_at) ' +
            'VALUES ($1, $2, $3, $4)', uuid4(), token, user['id'],
            datetime.now() + timedelta(days=30 if remember else 1))

        return {'success': True, 'token': token}


@login_bp.route('/change-password', methods=['POST'])
async def change_password():
    # Two potential forms of authentication here.
    # We use a prefix in the authorization header to determine it.
    #
    # Authorization: PasswordReset ... <- password reset, this serves as enough
    #                                     auth itself
    # Authorization: Bearer ...        <- generic password change, needs valid
    #                                     oldPassword
    if 'Authorization' not in request.headers:
        return no('Missing authorization.')

    auth_parts = request.headers.get('Authorization').split(' ')
    json = await request.get_json()

    if 'password' not in json:
        return no('Missing password.')

    if len(auth_parts) != 2:
        return no('Invalid authorization structure.')

    auth_type = auth_parts[0]
    auth_token = auth_parts[1]

    is_bearer = auth_type == 'Bearer'
    is_reset = auth_type == 'PasswordReset'

    if not is_bearer and not is_reset:
        return no('Invalid authorization type.')

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con

        if is_bearer:
            if 'oldPassword' not in json:
                return no('Missing oldPassword.')

            user = await con.fetchrow(GET_PASSWORD_AND_ID_BY_SESSION_QUERY,
                                      auth_token)

            if not user:
                return no('Invalid authorization.')

            if not bcrypt.checkpw(json['oldPassword'].encode('utf-8'),
                                  user['password_hashed'].encode('utf-8')):
                return no('Old password is incorrect.')

            user_id = user['id']
            field = 'id'
        else:
            email = await g.redis.get('login:password_reset:' + auth_token)
            if not email:
                return no('Invalid authorization.')
            user_id = email.decode('utf-8')
            field = 'email'

        hashed = bcrypt.hashpw(json['password'].encode('utf-8'),
                               bcrypt.gensalt()).decode('utf-8')

        user_id = await con.fetchval('UPDATE users SET password_hashed = $1 ' +
                                     f'WHERE {field} = $2 RETURNING id',
                                     hashed, user_id)

        await con.execute('DELETE FROM sessions WHERE user_id = $1', user_id)

        return {'success': True, 'message': ''}


@login_bp.route('/logout')
async def logout():
    if 'Authorization' not in request.headers:
        return no('Missing authorization.')

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con
        await con.execute('DELETE FROM sessions WHERE token = $1',
                          request.headers.get('Authorization'))
        return {'success': True, 'message': ''}
