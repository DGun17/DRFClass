# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin

# Register your models here.
from pastebin.models import Snippet
from rest_framework.authtoken.models import Token

admin.site.register(Snippet)
