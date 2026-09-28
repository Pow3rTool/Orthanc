from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("enrollment", "0018_alter_agentapp_options_agentapp_state")]
    operations = [
        migrations.AddField(
            model_name="enrollment", name="running_goos",
            field=models.CharField(blank=True, max_length=20),
        ),
        migrations.AddField(
            model_name="enrollment", name="running_shell",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name="enrollment", name="running_os_version",
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name="enrollment", name="self_update_supported",
            field=models.BooleanField(blank=True, null=True),
        ),
    ]
