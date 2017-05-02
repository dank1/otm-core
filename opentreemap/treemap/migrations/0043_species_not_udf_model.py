# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('treemap', '0042_auto_20170112_1603'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='species',
            name='udfs',
        ),
    ]
