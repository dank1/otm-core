# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations
import django.contrib.postgres.fields.hstore


class Migration(migrations.Migration):

    dependencies = [
        ('treemap', '0043_species_not_udf_model'),
    ]

    operations = [
        migrations.RenameField(
            model_name='mapfeature',
            old_name='udfs',
            new_name='hstore_udfs',
        ),
        migrations.AlterField(
            model_name='mapfeature',
            name='hstore_udfs',
            field=django.contrib.postgres.fields.hstore.HStoreField(
                default={}, db_index=True, db_column='udfs', blank=True),
        ),
        migrations.RenameField(
            model_name='tree',
            old_name='udfs',
            new_name='hstore_udfs',
        ),
        migrations.AlterField(
            model_name='tree',
            name='hstore_udfs',
            field=django.contrib.postgres.fields.hstore.HStoreField(
                default={}, db_index=True, db_column='udfs', blank=True),
        ),
        migrations.AlterField(
            model_name='userdefinedcollectionvalue',
            name='data',
            field=django.contrib.postgres.fields.hstore.HStoreField(),
        ),
    ]
