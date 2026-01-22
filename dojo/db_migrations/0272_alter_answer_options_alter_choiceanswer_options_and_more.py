
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0271_alter_input_type'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='answer',
            options={},
        ),
        migrations.AlterModelOptions(
            name='choiceanswer',
            options={},
        ),
        migrations.AlterModelOptions(
            name='choicequestion',
            options={},
        ),
        migrations.AlterModelOptions(
            name='textanswer',
            options={},
        ),
        migrations.AlterModelOptions(
            name='textquestion',
            options={},
        ),
]
