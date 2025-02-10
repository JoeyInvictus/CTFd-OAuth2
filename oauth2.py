from flask import session, redirect
from flask_dance.contrib import azure
import flask_dance.contrib

from CTFd.auth import confirm, register, reset_password, login
from CTFd.models import db, Users
from CTFd.utils import set_config
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user, logout_user

from CTFd import utils

def load(app):
    ########################
    # Plugin Configuration #
    ########################
    authentication_url_prefix = "/auth"
    oauth_client_id = utils.get_app_config('OAUTHLOGIN_CLIENT_ID')
    oauth_client_secret = utils.get_app_config('OAUTHLOGIN_CLIENT_SECRET')
    oauth_provider = utils.get_app_config('OAUTHLOGIN_PROVIDER')
    create_missing_user = utils.get_app_config('OAUTHLOGIN_CREATE_MISSING_USER')
    tenant_id = utils.get_app_config('OAUTHLOGIN_TENANT_ID')

    ##################
    # User Functions #
    ##################
    def retrieve_user_from_database(username):
        user = Users.query.filter_by(email=username).first()
        if user is not None:
            log('logins', "[{date}] {ip} - " + username + " - OAuth2 bridged user found")
            return user
    def create_user(username, displayName):
        with app.app_context():
            log('logins', "[{date}] {ip} - " + username + " - No OAuth2 bridged user found, creating user")
            user = Users(email=username, name=displayName.strip())
            db.session.add(user)
            db.session.commit()
            db.session.flush()
            return user
    def create_or_get_user(username, displayName):
        user = retrieve_user_from_database(username)
        if user is not None:
            return user
        if create_missing_user:
            return create_user(username, displayName)
        else:
            log('logins', "[{date}] {ip} - " + username + " - No OAuth2 bridged user found and not configured to create missing users")
            return None

    ##########################
    # Provider Configuration #
    ##########################
    provider_blueprints = {
        'azure': lambda: flask_dance.contrib.azure.make_azure_blueprint(
            login_url='/azure',
            client_id=oauth_client_id,
            client_secret=oauth_client_secret,
            redirect_url=authentication_url_prefix + "/azure/confirm",
            tenant=tenant_id)
    }

    def get_azure_user():
        user_info = flask_dance.contrib.azure.azure.get("/v1.0/me").json()
        return create_or_get_user(
            username=user_info["userPrincipalName"],
            displayName=user_info["displayName"])

    provider_users = {
        'azure': lambda: get_azure_user()
    }

    provider_blueprint = provider_blueprints[oauth_provider]() # Resolved lambda
    
    #######################
    # Blueprint Functions #
    #######################
    @provider_blueprint.route('/<string:auth_provider>/confirm', methods=['GET'])
    def confirm_auth_provider(auth_provider):
        if not auth_provider in provider_users:
            return redirect('/')

        provider_user = provider_users[oauth_provider]() # Resolved lambda
        session.regenerate()
        if provider_user is not None:
            login_user(provider_user)
        return redirect('/')

    app.register_blueprint(provider_blueprint, url_prefix=authentication_url_prefix)

    ###############################
    # Application Reconfiguration #
    ###############################
    # ('', 204) is "No Content" code
    set_config('registration_visibility', False)
    app.view_functions['auth.login'] = lambda: redirect(authentication_url_prefix + "/" + oauth_provider)
    app.view_functions['auth.register'] = lambda: ('', 204)
    app.view_functions['auth.reset_password'] = lambda: ('', 204)
    app.view_functions['auth.confirm'] = lambda: ('', 204)     