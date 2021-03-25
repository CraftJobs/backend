from bp.blueprint import Blueprint
from quart import g
import asyncpg
import aioredis


ping_bp = Blueprint('ping', __name__)


@ping_bp.route('/')
async def root():
    pool: asyncpg.Pool = g.pool

    async with pool.acquire() as con:
        con: asyncpg.Connection = con
        postgres_one = await con.fetchval('SELECT 1')

    redis_one = int(await g.redis.ping('1'))

    return {'p': postgres_one, 'r': redis_one, 'e': 1}

