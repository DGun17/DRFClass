from rest_framework.authentication import TokenAuthentication
from django.utils.deprecation import MiddlewareMixin
from datetime import datetime
from pastebin.models import AuthToken
from rest_framework.exceptions import ParseError


class CustomTokenAuthentication(TokenAuthentication):

    def get_model(self):
        if self.model is not None:
            return self.model
        from pastebin.models import AuthToken
        return AuthToken


class CustomTokenMiddleware(MiddlewareMixin):

    def process_request(self, request):
        try:
            token_key = request.META['HTTP_AUTHORIZATION'].split(' ')[1]
        except KeyError:
            pass
        except IndexError:
            raise ValueError("Token mal formed")
        else:
            try:
                token = AuthToken.objects.get(key=token_key)
            except AuthToken.DoesNotExist as e:
                raise ParseError(detail="Token Don't exist")
            else:
                expire_date = token.expire_date.replace(tzinfo=None)
                if not expire_date > datetime.now():
                    token.delete()
                    raise ParseError(detail='Token Expired')