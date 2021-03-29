from quart import Quart, g
from quart_cors import cors
from os import listdir
from hypercorn.asyncio import serve
from hypercorn.config import Config
import json
import asyncpg
import aioredis
import sendgrid
import http3
import asyncio
import os

from bp.gk import gk_bp
from bp.login import login_bp
from bp.ping import ping_bp
from bp.register import register_bp, register_debug_bp
from bp.users import users_bp

app = cors(Quart(__name__))

pool = None
redis = None
config = None
sg = None
http = None


def main():
    app.register_blueprint(gk_bp)
    app.register_blueprint(login_bp)
    app.register_blueprint(ping_bp)
    app.register_blueprint(register_bp)
    app.register_blueprint(users_bp)


@app.before_serving
async def second_main():
    global pool 
    global redis
    global config
    global sg
    global http

    config = load_config()
    http = http3.AsyncClient()

    if config['debug']:
        print('!!!!!!!!! BIG BAD SCARY WARNING !!!!!!!!! ')
        print('DEBUG MODE ENABLED! THIS WILL ALLOW USERS POWER THEY SHOULD')
        print('NOT HAVE. MAKE ABSOLUTELY SURE THIS IS INTENTIONAL.')
        print('!!!!!!!!! BIG BAD SCARY WARNING !!!!!!!!! ')

        app.register_blueprint(register_debug_bp)

    pool = await asyncpg.create_pool(
        user=config['db_user'],
        dsn=f"postgres://{config['db_user']}:{config['db_password']}" + 
            f"@{config['db_host']}:{config['db_port']}/{config['db_name']}")

    async with pool.acquire() as con:
        con: asyncpg.Connection = con

        version = 0

        await con.execute('CREATE TABLE IF NOT EXISTS migration_version (version BIGINT)')

        if await con.fetchval('SELECT COUNT(*) FROM migration_version') == 0:
            await con.execute('INSERT INTO migration_version VALUES (0)')

        mig_version = await con.fetchval('SELECT version FROM migration_version')

        versions = []
        full_names = []

        for file in listdir('migrations'):
            version = int(file.split('-')[0])
            versions.append(version)
            full_names.append(file)

        versions.sort()

        for version in versions:
            if version <= mig_version:
                print('Skipping ' + str(version) + ' - too old')
                continue
            ver_file = list(filter(
                lambda name: name[:len(str(version))] == str(version),
                full_names))[0]

            print('Migrating ' + ver_file)

            with open('migrations/' + ver_file, 'r') as file:
                lines = []
                for line in file.readlines():
                    lines.append(line)
                    if len(line.strip()) > 0 and line.strip()[-1] == ';':
                        await con.execute('\n'.join(lines))
                        lines = []
                        continue
                await con.execute('UPDATE migration_version SET version = $1', version)

    redis = await aioredis.create_redis_pool(
        f"redis://{config['redis_host']}:{config['redis_port']}", 
        password=config['redis_password']
    )

    sg = sendgrid.SendGridAPIClient(api_key=config['sg_key'])

    loop = asyncio.get_event_loop()
    loop.create_task(session_expirer())


@app.before_request
async def before():
    g.pool = pool
    g.redis = redis
    g.config = config
    g.sg = sg
    g.http = http


def load_config():
    with open('config.json', 'r') as file:
        return json.load(file)


async def session_expirer():
    while True:
        await asyncio.sleep(5)
        async with pool.acquire() as con:
            con: asyncpg.Connection = con
            rows = await con.fetch(
                'DELETE FROM sessions WHERE expires_at <= NOW() RETURNING id, '
                'expires_at')
            for row in rows:
                print(f'[session expirer] expired session {row["id"]} - '
                      f'expired at {row["expires_at"]}')
            if len(rows) > 0:
                print(f'[session expirer] expired {len(rows)} sessions')


if __name__ == "__main__":
    os.environ['TZ'] = 'America/Los_Angeles'
    main()
    config = Config()
    config.bind = 'localhost:7085'
    asyncio.run(serve(app, config))
