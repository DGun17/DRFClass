from django.conf.urls import url
from rest_framework.routers import SimpleRouter

from pastebin.views import snippet_view, SnippetView, detail_view, list_view, update_view, delete_view, \
    SnippetViewSet, SnippetModelViewSet
from .views import get_snippets, obtain_auth_token, logout_token

router = SimpleRouter()

router.register(r'viewset', SnippetViewSet, base_name='snippet')
router.register(r'model', SnippetModelViewSet)
urls = router.urls

app_name = "pastebin"
urlpatterns = [
                  url(r'^$', get_snippets, name='snippets'),
                  url(r'^(?P<pk>\d+)$', get_snippets, name='snippets'),
                  url(r'^cbv/$', snippet_view),
                  url(r'^cbv/(?P<pk>\d+)/$', snippet_view),
                  url(r'^login/$', obtain_auth_token),
                  url(r'^logout/$', logout_token)
              ] + urls
