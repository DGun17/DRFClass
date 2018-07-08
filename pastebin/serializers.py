from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.renderers import JSONRenderer

from pastebin.models import Snippet


class NameUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name')


class SnippetSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=140)
    code = serializers.CharField()
    lang = serializers.ChoiceField(choices=Snippet.LANGS)


class SnippetModelSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    user = NameUserSerializer(read_only=True)
    title = serializers.CharField(required=False)
    code = serializers.CharField(required=False)
    lang = serializers.CharField(required=False)

    class Meta:
        model = Snippet
        fields = ('id', 'title', 'code', 'lang', 'user')
