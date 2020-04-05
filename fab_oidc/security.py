from flask_appbuilder.security.manager import AUTH_OID
from flask_appbuilder.security.sqla.manager import SecurityManager
from flask_oidc import OpenIDConnect
from .views import AuthOIDCView
from logging import getLogger
log = getLogger(__name__)


class OIDCSecurityManagerMixin:

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            app = self.appbuilder.get_app
            app.config.setdefault('OIDC_MAPPING_USERNAME_FILED', 'sub')
            app.config.setdefault('OIDC_MAPPING_FIRST_NAME_FIELD', 'nickname')
            app.config.setdefault('OIDC_MAPPING_LAST_NAME_FIELD', 'name')
            app.config.setdefault('OIDC_MAPPING_USER_ROLE_FIELD', 'user_role')
            app.config.setdefault('OIDC_AIRFLOW_ROLE_MAP', None)
            self.oid = OpenIDConnect(app)
            self.authoidview = AuthOIDCView


class OIDCSecurityManager(OIDCSecurityManagerMixin, SecurityManager):
    pass


try:
    from airflow.www_rbac.security import AirflowSecurityManager

    class AirflowOIDCSecurityManager(OIDCSecurityManagerMixin,
                                     AirflowSecurityManager):
        pass
except ImportError:
    log.debug('Airflow not installed')

try:
    from superset.security import SupersetSecurityManager

    class SupersetOIDCSecurityManager(OIDCSecurityManagerMixin,
                                      SupersetSecurityManager):
        pass
except ImportError:
    log.debug('Superset not installed')
