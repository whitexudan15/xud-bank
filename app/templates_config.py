from jinja2 import FileSystemLoader, Environment
from starlette.templating import Jinja2Templates

_env = Environment(
    loader=FileSystemLoader([
        "app/templates",
        "secureDataMonitor/templates",
    ]),
    autoescape=True,
)
templates = Jinja2Templates(env=_env)