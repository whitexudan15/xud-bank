from jinja2 import FileSystemLoader, Environment, FileSystemBytecodeCache
from starlette.templating import Jinja2Templates
import os

# Enable bytecode caching for production performance
cache_dir = os.path.join(os.path.dirname(__file__), '..', '.cache', 'jinja2')
os.makedirs(cache_dir, exist_ok=True)

_env = Environment(
    loader=FileSystemLoader([
        "app/templates",
        "secureDataMonitor/templates",
    ]),
    autoescape=True,
    bytecode_cache=FileSystemBytecodeCache(cache_dir),
    auto_reload=False,
)
templates = Jinja2Templates(env=_env)