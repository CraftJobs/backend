from bp.blueprint import Blueprint
from util.resp import no
from quart import g, request as quart_rq, Request
from typing import Dict, List
from uuid import uuid4
from hashlib import md5
from os.path import isfile
from os import remove
from datetime import datetime

import asyncpg

users_bp = Blueprint('users', __name__)

USER_SELECT_QUERY = """SELECT id, avatar_url, full_name, username, rate_lower, 
rate_higher, role, rate_range_type, admin, description FROM users 
WHERE username_lower = $1
"""

REP_LOG_QUERY = """SELECT 
    from_user_id,
    message, 
    time,
    amount,
    users.username as from_username,
    users.full_name as from_full_name
FROM reputation_log INNER JOIN users ON (users.id = from_user_id) 
WHERE to_user_id = $1"""


USER_BY_SESSION_QUERY = """SELECT
    user_id as id,
    users.admin as admin,
    users.username as username
FROM sessions INNER JOIN users ON (users.id = user_id) 
WHERE token = $1
"""


@users_bp.route('/<username>')
async def get_user(username: str):
    request: Request = quart_rq

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con
        db_user = await con.fetchrow(USER_SELECT_QUERY, username.lower())

        authed_as = None
        self = {}

        if 'Authorization' in request.headers:
            db_self = await con.fetchrow(USER_BY_SESSION_QUERY,
                                         request.headers.get('Authorization'))

            if db_self:
                authed_as = db_self['id']
                self['username'] = db_self['username']
                self['admin'] = db_self['admin']
                self['isSelf'] = db_self['username'].lower() == username.lower()
                self['isFollowing'] = False
                self['reputationGiven'] = 0
                self['plusReputationFollowing'] = []
                self['minusReputationFollowing'] = []

        if not db_user:
            return no('not_found')

        user_id = db_user['id']

        db_looking_for = await con.fetch(
            'SELECT looking_for_type FROM looking_for WHERE user_id = $1',
            user_id)

        rate_lower = db_user['rate_lower']
        rate_higher = db_user['rate_higher']
        rate_range = []

        if rate_lower != -1:
            rate_range.append(rate_lower)

            if rate_higher != -1:
                rate_range.append(rate_higher)

        rep_log = await con.fetch(REP_LOG_QUERY, user_id)

        total_rep = 0
        formatted_rep_log = []
        rep_amount_by_user = {}

        for rep_entry in rep_log:
            total_rep += rep_entry['amount']
            formatted_rep_log.append({
                'user': rep_entry['from_username'],
                'amount': rep_entry['amount'],
                'time': rep_entry['time'].isoformat(),
                'message': rep_entry['message'],
                'userFullName': rep_entry['from_full_name']
            })
            rep_amount_by_user[rep_entry['from_user_id']] = {
                'amount': rep_entry['amount'],
                'user': rep_entry['from_username']}

            if authed_as and rep_entry['from_user_id'] == authed_as:
                self['reputationGiven'] = rep_entry['amount']

        if authed_as:
            db_following = await con.fetch(
                'SELECT following_user_id FROM following ' +
                'WHERE follower_user_id = $1', authed_as)

            for follow_row in db_following:
                following_id = follow_row['following_user_id']

                if following_id == user_id:
                    self['isFollowing'] = True

                if following_id in rep_amount_by_user:
                    following_rep = rep_amount_by_user[following_id]

                    if following_rep['amount'] > 0:
                        self['plusReputationFollowing'].append(following_rep['user'])
                    else:
                        self['minusReputationFollowing'].append(following_rep['user'])

        connections = {}

        db_connections = await con.fetch(
            'SELECT connection_type, link FROM connections WHERE user_id = $1',
            user_id)

        for connection_row in db_connections:
            connections[connection_row['connection_type']] = \
                connection_row['link']

        user = {
            'avatarUrl': db_user['avatar_url'],
            'fullName': db_user['full_name'],
            'username': db_user['username'],
            'lookingFor': list(filter(lambda x: x['looking_for_type'],
                                      db_looking_for)),
            'rateRange': rate_range,
            'reputation': total_rep,
            'role': db_user['role'],
            'experience': [],  # TODO
            'rateRangeType': db_user['rate_range_type'],
            'languages': [],  # TODO
            'admin': db_user['admin'],
            'description': db_user['description'],
            'reputationLog': formatted_rep_log,
            'connections': connections,
        }

        ret = {'success': True, 'user': user}

        if authed_as:
            ret['self'] = self

        return ret

ALPHANUMERIC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
GITHUB_CHARS = ALPHANUMERIC + '-'
EMAIL_CHARS = ALPHANUMERIC + '+.@'
TWITTER_CHARS = ALPHANUMERIC + '_'


def github_validator(link: str):
    if len(link) > 39:
        return False

    # Cannot begin or end with a hyphen
    if link[0] == '-' or link[-1] == '-':
        return False

    was_hyphen = False

    for _, char in enumerate(link):
        if char not in GITHUB_CHARS:
            return False

        is_hyphen = char == '-'

        # No consecutive hyphens
        if was_hyphen and is_hyphen:
            return False

        was_hyphen = is_hyphen

    return True


def email_validator(link: str):
    if '@' not in link:
        return False

    for _, char in enumerate(link):
        if char not in EMAIL_CHARS:
            return False

    # Let's hope people don't have stupid long emails
    if len(link) > 64:
        return False

    return True


def discord_validator(link: str):
    # v  i  o  l  e  t  #  1  3  3  7
    #                   -5 -4 -3 -2 -1
    if link[-5] != '#':
        return False

    if not link[-4:].isnumeric():
        return False

    if len(link.split('#')[0]) > 32:
        return False

    return True


def twitter_validator(link: str):
    if len(link) > 15:
        return False

    for _, char in enumerate(link):
        if char not in TWITTER_CHARS:
            return False

    return True


ROLES = ['DEVELOPER', 'MANAGER', 'SYSADMIN', 'OTHER']
RATE_RANGE_TYPES = ['HOURLY', 'FLAT']
CONNECTION_VALIDATORS = {
    'GITHUB': github_validator,
    'EMAIL': email_validator,
    'DISCORD': discord_validator,
    'TWITTER': twitter_validator,
}


@users_bp.route('/@me/edit', methods=['POST'])
async def edit_me():
    request: Request = quart_rq
    json: Dict = await request.get_json()

    if 'Authorization' not in request.headers:
        return no('Missing authorization.')

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con

        user_id = await con.fetchval(
            'SELECT user_id FROM sessions WHERE token = $1',
            request.headers.get('Authorization'))

        if not user_id:
            return no('Invalid authorization.')

        main_query = 'UPDATE users SET '
        set_idx = 1
        set_args = []

        for key, value in json.items():
            str_value: str = value

            if key == 'fullName':
                main_query += f'full_name = ${set_idx}, '

                if len(str_value) > 32:
                    return no('Full name must be less than 32 characters.')

                set_args.append(str_value)
                set_idx += 1
            elif key == 'rateRange':
                intl_value: List[int] = value
                last_value = -1

                if len(intl_value) > 2:
                    return no('Invalid rate range')

                for rate in intl_value:
                    if rate > 32767 or rate < 0:
                        return no('Rates must be between 0 and 32767.')
                    if rate < last_value:
                        return no('End of rate range must not be less than start.')
                    last_value = rate

                rate_lower = -1 if len(intl_value) < 1 else intl_value[0]
                rate_higher = -1 if len(intl_value) < 2 else intl_value[1]

                main_query += f'rate_lower = ${set_idx}, rate_higher = ${set_idx + 1}, '
                set_args.append(rate_lower)
                set_args.append(rate_higher)
                set_idx += 2
            elif key == 'role':
                if str_value not in ROLES:
                    return no('Invalid role.')

                main_query += f'role = ${set_idx}, '
                set_args.append(str_value)
                set_idx += 1
            elif key == 'rateRangeType':
                if str_value not in RATE_RANGE_TYPES:
                    return no('Invalid rate range type.')

                main_query += f'rate_range_type = ${set_idx}, '
                set_args.append(str_value)
                set_idx += 1
            elif key == 'description':
                if len(str_value) > 2000:
                    return no('Description cannot be greater than 2000 characters.')

                main_query += f'description = ${set_idx}, '
                set_args.append(str_value)
                set_idx += 1
            elif key == 'connections':
                strd_value: Dict[str, str] = value

                for con_key, con_val in strd_value.items():
                    if con_key not in CONNECTION_VALIDATORS:
                        return no('Invalid connection: ' + con_key + '.')

                    if not CONNECTION_VALIDATORS[con_key](con_val):
                        return no('Invalid ' + con_key.lower())

                    await con.execute('INSERT INTO connections (id, ' +
                                      'user_id, connection_type, link) ' +
                                      'VALUES ($1, $2, $3, $4) ON CONFLICT ' +
                                      '(user_id, connection_type) DO UPDATE ' +
                                      'SET link = $4', uuid4(), user_id,
                                      con_key, con_val)

        # No additions
        if main_query[-4:] == 'SET ':
            return {'success': True, 'message': 'Look ma, I\'m a reverse engineer!'}

        main_query = main_query[:-2]  # remove last comma and space
        main_query += ' WHERE id = $' + str(set_idx)
        set_args.append(user_id)

        await con.execute(main_query, *set_args)

    return {'success': True, 'message': 'Look ma, I\'m a reverse engineer!'}


@users_bp.route('/@me/avatar', methods=['POST'])
async def me_avatar():
    request: Request = quart_rq

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con

        if 'Authorization' not in request.headers:
            return no('Missing authorization.')

        user_id = await con.fetchval(
            'SELECT user_id FROM sessions WHERE token = $1',
            request.headers.get('Authorization'))

        if not user_id:
            return no('Invalid authorization.')

        files = await request.files

        if 'avatar' not in files:
            return no('Missing avatar')

        avatar = files['avatar']
        avatar.save('avatartemp/' + str(user_id))

        with open('avatartemp/' + str(user_id), 'rb') as file:
            file_bytes = file.read()
            md5sum = md5(file_bytes).hexdigest()

            path = g.config['avatar_dir'] + '/' + md5sum

            if not isfile(path):
                with open(path, 'wb') as avatar_file:
                    avatar_file.write(file_bytes)

        remove('avatartemp/' + str(user_id),)

        url = 'https://static.craftjobs.net/avatars/' + md5sum
        await con.execute('UPDATE users SET avatar_url = $1 WHERE id = $2',
                          url, user_id)

        return {'success': True, 'message': url}


@users_bp.route('/<username>/follow', methods=['POST'])
async def follow(username: str):
    request: Request = quart_rq

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con

        if 'Authorization' not in request.headers:
            return no('Missing authorization.')

        user_id = await con.fetchval(
            'SELECT user_id FROM sessions WHERE token = $1',
            request.headers.get('Authorization'))

        if not user_id:
            return no('Invalid authorization.')

        following_user_id = await con.fetchval(
            'SELECT id FROM users WHERE username_lower = $1', username.lower())

        if not following_user_id:
            return no('User not found.')

        await con.execute(
            'INSERT INTO following (id, follower_user_id, following_user_id) ' +
            'VALUES ($1, $2, $3) ON CONFLICT (follower_user_id, ' +
            'following_user_id) DO NOTHING', uuid4(), user_id,
            following_user_id)

        return {'success': True, 'message': ''}


@users_bp.route('/<username>/unfollow', methods=['POST'])
async def unfollow(username: str):
    request: Request = quart_rq

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con

        if 'Authorization' not in request.headers:
            return no('Missing authorization.')

        user_id = await con.fetchval(
            'SELECT user_id FROM sessions WHERE token = $1',
            request.headers.get('Authorization'))

        if not user_id:
            return no('Invalid authorization.')

        following_user_id = await con.fetchval(
            'SELECT id FROM users WHERE username_lower = $1', username.lower())

        if not following_user_id:
            return no('User not found.')

        await con.execute('DELETE FROM following WHERE ' +
                          'follower_user_id = $1 AND following_user_id = $2',
                          user_id, following_user_id)

        return {'success': True, 'message': ''}


@users_bp.route('/<username>/reputation', methods=['POST'])
async def rep(username: str):
    request: Request = quart_rq
    json = await request.get_json()

    if 'amount' not in json:
        return no('Missing amount.')
    if 'message' not in json:
        return no('Missing message')

    amount = json['amount']
    message = json['message']

    if len(message) > 255:
        return no('Message cannot be more than 255 characters.')

    async with g.pool.acquire() as con:
        con: asyncpg.Connection = con

        if 'Authorization' not in request.headers:
            return no('Missing authorization.')

        user = await con.fetchrow(
            'SELECT user_id as id, u.admin as admin FROM sessions ' +
            'INNER JOIN users u on u.id = sessions.user_id WHERE token = $1',
            request.headers.get('Authorization'))

        if not user:
            return no('Invalid authorization.')

        if abs(amount) != 1 and not user['admin']:
            return no('Invalid amount.')

        target_user_id = await con.fetchval(
            'SELECT id FROM users WHERE username_lower = $1', username.lower())

        if not target_user_id:
            return no('User not found.')

        await con.execute('DELETE FROM reputation_log WHERE ' +
                          'from_user_id = $1 AND to_user_id = $2', user['id'],
                          target_user_id)

        await con.execute('INSERT INTO reputation_log (id, from_user_id, ' +
                          'to_user_id, amount, message) ' +
                          'VALUES ($1, $2, $3, $4, $5)', uuid4(), user['id'],
                          target_user_id, amount, message)

        return {'success': True, 'message': ''}
