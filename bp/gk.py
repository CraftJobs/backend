from bp.blueprint import Blueprint
from quart import request, g

gk_bp = Blueprint('gk', __name__)

VALID_FIELDS = ['admin', 'alpha', 'omi_admin']  # Prevent SQLi


@gk_bp.route('/check', methods=['POST'])
async def check():
    json = await request.get_json()

    if 'token' not in json:
        return {'valid': False, 'field': False}
    if 'field' not in json:
        return {'valid': False, 'field': False}

    field = json['field']
    token = json['token']

    if field not in VALID_FIELDS:
        return {'valid': False, 'field': False}

    async with g.pool.acquire() as con:
        row = await con.fetchrow(f'SELECT u.{field} as {field}, u.id as id  '
                                 f'FROM sessions INNER JOIN users u ON '
                                 f'sessions.user_id = u.id WHERE token = $1',
                                 token)

        if not row:
            return {'valid': False, 'field': False}

        return {'valid': True, 'field': field[field]}
