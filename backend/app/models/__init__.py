"""
Import every model module here so that a single `import app.models` (done
once, in app.core.init_db) registers all tables on Base.metadata before
create_all() runs. Without this, tables defined in files that are never
imported would silently not be created.
"""
from app.models.user import User  # noqa: F401
from app.models.agent import Agent  # noqa: F401
from app.models.log import Log  # noqa: F401
from app.models.rule import DetectionRule  # noqa: F401
from app.models.incident import Incident  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.soar import SoarAction  # noqa: F401
from app.models.mfa import UserMFA  # noqa: F401
