# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations
from django.contrib.postgres.operations import HStoreExtension


class Migration(migrations.Migration):

    dependencies = [
        ('treemap', '0042_auto_20170112_1603'),
    ]

    operations = [
        HStoreExtension()
    ]
