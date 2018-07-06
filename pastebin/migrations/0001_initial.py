# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-07-05 19:49
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Snippet',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateField(auto_now_add=True)),
                ('title', models.CharField(max_length=140)),
                ('code', models.TextField()),
                ('lang', models.CharField(choices=[('python', 'Python'), ('javascript', 'Javascript')], max_length=40)),
            ],
        ),
    ]