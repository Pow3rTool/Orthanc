"""Collapse the old three-class verb vocabulary to two honest tiers.

Old: read | run | full. New: readonly | full. `read` becomes `readonly`; `run`
becomes `full` (run always implied shell, and shell is mutation — so a run grant
already carried full power). Idempotent and reversible-ish.
"""
from django.db import migrations


def forward(apps, schema_editor):
    Grant = apps.get_model("enrollment", "Grant")
    Grant.objects.filter(verb_class="read").update(verb_class="readonly")
    Grant.objects.filter(verb_class="run").update(verb_class="full")


def backward(apps, schema_editor):
    Grant = apps.get_model("enrollment", "Grant")
    # Best-effort inverse: readonly -> read. (full is ambiguous: was it run or
    # full originally? leave as full — no data loss, just coarser history.)
    Grant.objects.filter(verb_class="readonly").update(verb_class="read")


class Migration(migrations.Migration):

    dependencies = [
        ("enrollment", "0008_principal_alter_grant_verb_class_grant_principal"),
    ]

    operations = [
        migrations.RunPython(forward, backward),
    ]
