# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.http import JsonResponse


# Create your views here.
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet, ModelViewSet

from pastebin.models import Snippet, AuthToken
from pastebin.serializers import SnippetModelSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework import exceptions
from rest_framework.permissions import IsAuthenticated
from datetime import timedelta
from django.utils import timezone


@csrf_exempt
@api_view(http_method_names=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def get_snippets(request, pk=None):
    if request.method.upper() == 'GET':
        if pk is not None:
            snippet = get_object_or_404(Snippet, pk=pk)
            serializer = SnippetModelSerializer(snippet)
        else:
            snippets = Snippet.objects.all()
            serializer = SnippetModelSerializer(snippets, many=True)

        return JsonResponse(serializer.data)

    if request.method.upper() == 'POST':
        serializer = SnippetModelSerializer(data=request.data)
        if serializer.is_valid():
            obj = serializer.save()
            obj.user = User.objects.get(pk=1)
            obj.save()
            serializer = SnippetModelSerializer(obj)
            return JsonResponse(serializer.data, status=201)

    if request.method.upper() in ['PUT', 'PATCH']:
        serializer = SnippetModelSerializer(data=request.data)
        if serializer.is_valid():
            obj = Snippet.objects.get(pk=pk)
            obj.title = request.data['title']
            obj.code = request.data['code']
            obj.lang = request.data['lang']
            obj.save()
            serializer = SnippetModelSerializer(obj)
        return JsonResponse(serializer.data, status=201)

    if request.method.upper() == "DELETE":
        obj = get_object_or_404(Snippet.objects.filter(pk=pk))
        obj.delete()
        return Response(status=204)


class SnippetView(APIView):
    def get(self, request, pk=None, *args, **kwargs):
        if pk is not None:
            snippet = get_object_or_404(Snippet, pk=pk)
            serializer = SnippetModelSerializer(snippet)
        else:
            snippets = Snippet.objects.all()
            serializer = SnippetModelSerializer(snippets, many=True)

        return JsonResponse(serializer.data, safe=False)

    def post(self, request, *args, **kwargs):
        serializer = SnippetModelSerializer(data=request.data)
        if serializer.is_valid():
            obj = serializer.save()
            obj.user = User.objects.get(pk=1)
            obj.save()
            serializer = SnippetModelSerializer(obj)
            return JsonResponse(serializer.data, status=201)

    def put(self, request, pk, *args, **kwargs):
        serializer = SnippetModelSerializer(data=request.data)
        if serializer.is_valid():
            obj = Snippet.objects.get(pk=pk)
            obj.title = request.data['title']
            obj.code = request.data['code']
            obj.lang = request.data['lang']
            obj.save()
            serializer = SnippetModelSerializer(obj)
        return JsonResponse(serializer.data, status=201)

    def delete(self, request, pk, *args, **kwargs):
        obj = get_object_or_404(Snippet.objects.filter(pk=pk))
        obj.delete()
        return Response(status=204)


snippet_view = SnippetView.as_view()


class SnippetViewSet(ViewSet):
    permission_classes = (IsAuthenticated, )

    def retrieve(self, request, pk=None):
        snippet = get_object_or_404(Snippet, pk=pk)
        serializer = SnippetModelSerializer(snippet)
        return JsonResponse(serializer.data)

    def list(self, request):
        snippets = Snippet.objects.all()
        serializer = SnippetModelSerializer(snippets, many=True)
        return JsonResponse(serializer.data, safe=False)

    def update(self, request, pk=None):
        serializer = SnippetModelSerializer(data=request.data)
        if serializer.is_valid():
            obj = Snippet.objects.get(pk=pk)
            obj.title = request.data['title']
            obj.code = request.data['code']
            obj.lang = request.data['lang']
            obj.save()
            serializer = SnippetModelSerializer(obj)
        return JsonResponse(serializer.data, status=201)

    def partial_update(self, request, pk=None, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = Snippet.objects.get(pk=pk)
        serializer = SnippetModelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        for key, value in serializer.data.items():
            setattr(instance, key, value)
        instance.save()
        return Response(serializer.data)

    def destroy(self, request, pk):
        obj = get_object_or_404(Snippet.objects.filter(pk=pk))
        obj.delete()
        return Response(status=204)

    def create(self, request):
        serializer = SnippetModelSerializer(data=request.data)
        if serializer.is_valid():
            obj = serializer.save()
            obj.user = User.objects.get(pk=1)
            obj.save()
            serializer = SnippetModelSerializer(obj)
            return JsonResponse(serializer.data, status=201)


detail_view = SnippetViewSet.as_view({'get': 'retrieve'})
list_view = SnippetViewSet.as_view({'get': 'list'})
update_view = SnippetViewSet.as_view({'put': 'update'})
delete_view = SnippetViewSet.as_view({'delete': 'destroy'})


class SnippetModelViewSet(ModelViewSet):
    queryset = Snippet.objects.all()
    serializer_class = SnippetModelSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class LoginAPI(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        sessions = AuthToken.objects.filter(user=user)
        if len(sessions) < 5:
            token = AuthToken.objects.create(user=user, expire_date=self._get_expire_time())  # Create a token each login request
        else:
            raise exceptions.AuthenticationFailed(detail='You have maximum login session (5)')
        return Response({'token': token.key})

    @classmethod
    def _get_expire_time(cls):
        max_age = 300  # Number of seconds to expire session (5 Minutes)
        expire_time = timezone.now() + timedelta(seconds=max_age)
        return expire_time


class LogoutAPI(APIView):

    def get(self, request, *args, **kwargs):
        if getattr(request.user, 'is_anonymous') and getattr(request, 'auth') is not None:
            raise exceptions.NotAuthenticated(detail='User not logged')
        else:
            token = request.auth
            try:
                AuthToken.objects.get(key=token.key)
            except Exception as e:
                raise exceptions.NotAuthenticated(detail=e)
            else:
                token.delete()
                return Response({'message': 'Logout successfully'})


obtain_auth_token = LoginAPI.as_view()
logout_token = LogoutAPI.as_view()
