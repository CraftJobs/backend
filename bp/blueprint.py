import quart
from typing import Callable


class Blueprint(quart.Blueprint):
    def __init__(self, *args, **kwargs):
        kwargs['url_prefix'] = '/v1/' + args[0]
        super().__init__(*args, **kwargs)

    def route(self, *args, **kwargs) -> Callable:
        kwargs['strict_slashes'] = False
        return super().route(*args, **kwargs)
