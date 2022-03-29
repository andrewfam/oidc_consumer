from mozilla_django_oidc.auth import OIDCAuthenticationBackend

def logout_redirect_uri(request):
    messages.success(request, f'Signed out successfully') # -> This is optional
    id_token = request.session['oidc_id_token']
    provider_url = 'http(s)://{auth-app-domain-or-host}'
    logout_url = f'{provider_url}/openid/end-session/?id_token_hint={id_token}&post_logout_redirect_uri=http://{request.get_host()}/'
    return logout_url

# -> Save Custom User from the Auth App
class AuthManager(OIDCAuthenticationBackend):
    def create_user(self, claims):
        import pdb; pdb.set_trace()
        user = super(AuthManager, self).create_user(claims)

        user.first_name = claims.get('given_name', '')
        user.last_name = claims.get('family_name', '')

        user.id_number = claims.get('id_number', '')
        user.user_type = claims.get('user_type', '')
        user.save()

    def verify_claims(self, claims):
        import pdb; pdb.set_trace()
        verified = super(AuthManager, self).verify_claims(claims)
        id_number = claims.get('id_number')
        profile = claims.get('profile')
        return verified and id_number and profile

    def authenticate(self, request, **kwargs):
        """Authenticates a user based on the OIDC code flow."""

        self.request = request
        if not self.request:
            return None

        state = self.request.GET.get('state')
        code = self.request.GET.get('code')
        nonce = kwargs.pop('nonce', None)

        if not code or not state:
            return None

        reverse_url = self.get_settings('OIDC_AUTHENTICATION_CALLBACK_URL',
                                        'oidc_authentication_callback')

        token_payload = {
            'client_id': self.OIDC_RP_CLIENT_ID,
            'client_secret': self.OIDC_RP_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': absolutify(
                self.request,
                reverse(reverse_url)
            ),
        }

        # Get the token
        token_info = self.get_token(token_payload)
        id_token = token_info.get('id_token')
        access_token = token_info.get('access_token')

        # Validate the token
        payload = self.verify_token(id_token, nonce=nonce)

        if payload:
            self.store_tokens(access_token, id_token)
            try:
                return self.get_or_create_user(access_token, id_token, payload)
            except SuspiciousOperation as exc:
                LOGGER.warning('failed to get or create user: %s', exc)
                return None

        return None
