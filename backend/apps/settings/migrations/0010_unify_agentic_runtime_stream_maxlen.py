# Generated manually for Stream Maxlen unification.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("settings", "0009_remove_agenticruntimeconfig_module_block_ms"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="agenticruntimeconfig",
            name="module_stream_maxlen",
        ),
        migrations.RenameField(
            model_name="agenticruntimeconfig",
            old_name="webhook_stream_maxlen",
            new_name="stream_maxlen",
        ),
    ]
