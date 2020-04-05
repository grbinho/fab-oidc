import os
from flask import redirect, request
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from flask_admin import expose
from urllib.parse import quote


class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):

        app = self.appbuilder.get_app
        sm = self.appbuilder.sm
        oidc = sm.oid

        username_field = app.config['OIDC_MAPPING_USERNAME_FILED']
        first_name_field = app.config['OIDC_MAPPING_FIRST_NAME_FIELD']
        last_name_field = app.config['OIDC_MAPPING_LAST_NAME_FIELD']
        user_role_field = app.config['OIDC_MAPPING_USER_ROLE_FIELD']
        airflow_role_map = dict(app.config['OIDC_AIRFLOW_ROLE_MAP'])
        default_airflow_role = app.config['AUTH_USER_REGISTRATION_ROLE']

        def get_airflow_role(oidc_role):
            if airflow_role_map:
                return airflow_role_map.get(oidc_role, default_airflow_role)
            else:
                return default_airflow_role

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))

            if user is None:
                info = oidc.user_getinfo([
                    username_field,
                    first_name_field,
                    last_name_field,
                    user_role_field,
                    'email',
                ])

                user = sm.add_user(
                    username=info.get(username_field),
                    first_name=info.get(first_name_field),
                    last_name=info.get(last_name_field),
                    email=info.get('email'),
                    role=sm.find_role(get_airflow_role(info.get(user_role_field)))
                )

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_url = request.url_root.strip(
            '/') + self.appbuilder.get_url_for_login

        logout_uri = oidc.client_secrets.get(
            'issuer') + '/protocol/openid-connect/logout?redirect_uri='
        if 'OIDC_LOGOUT_URI' in self.appbuilder.app.config:
            logout_uri = self.appbuilder.app.config['OIDC_LOGOUT_URI']

        return redirect(logout_uri + quote(redirect_url))
