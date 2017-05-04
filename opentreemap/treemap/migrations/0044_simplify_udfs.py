# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.contrib.postgres.fields.hstore


class Migration(migrations.Migration):

    dependencies = [
        ('treemap', '0043_species_not_udf_model'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='mapfeature',
            name='udfs',
        ),
        migrations.RemoveField(
            model_name='tree',
            name='udfs',
        ),
        migrations.AddField(
            model_name='mapfeature',
            name='hstore_udfs',
            field=django.contrib.postgres.fields.hstore.HStoreField(db_index=True, null=True, db_column='udfs', blank=True),
        ),
        migrations.AddField(
            model_name='tree',
            name='hstore_udfs',
            field=django.contrib.postgres.fields.hstore.HStoreField(db_index=True, null=True, db_column='udfs', blank=True),
        ),
        migrations.AlterField(
            model_name='userdefinedcollectionvalue',
            name='data',
            field=django.contrib.postgres.fields.hstore.HStoreField(),
        ),
    ]
