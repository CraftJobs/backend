from bp.blueprint import Blueprint
from quart import g, request
from util.resp import no
from secrets import token_hex
from datetime import datetime, timedelta
from uuid import uuid4
import asyncpg
import bcrypt

login_bp = Blueprint('login', __name__)


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
