from rest_framework.authentication import TokenAuthentication


class CustomTokenAuthentication(TokenAuthentication):

    def get_model(self):
        if self.model is not None:
            return self.model
        from pastebin.models import AuthToken
        return AuthToken
