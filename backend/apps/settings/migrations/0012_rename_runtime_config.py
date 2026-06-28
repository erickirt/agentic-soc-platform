# Generated manually to rename runtime settings.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("settings", "0011_rename_setting_tables"),
    ]

    operations = [
        migrations.RenameModel(
            old_name="AgenticRuntimeConfig",
            new_name="RuntimeConfig",
        ),
        migrations.AlterModelTable(
            name="runtimeconfig",
            table="setting_runtime_config",
        ),
    ]
