"""empty message

Revision ID: d370c5101939
Revises: 308b95ba816b
Create Date: 2016-12-05 17:15:21.847079

"""

# revision identifiers, used by Alembic.
revision = 'd370c5101939'
down_revision = '308b95ba816b'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('alarm_record',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('content', sa.String(length=200), nullable=True),
    sa.Column('content_md5', sa.String(length=32), nullable=True),
    sa.Column('alarm_type', sa.SmallInteger(), nullable=True),
    sa.Column('alarm_level', sa.SmallInteger(), nullable=True),
    sa.Column('called_record_id', sa.Integer(), nullable=True),
    sa.Column('voice_notify_callback_id', sa.Integer(), nullable=True),
    sa.Column('state', sa.SmallInteger(), nullable=True),
    sa.Column('create_time', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alarm_record_content_md5'), 'alarm_record', ['content_md5'], unique=False)
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_alarm_record_content_md5'), table_name='alarm_record')
    op.drop_table('alarm_record')
    ### end Alembic commands ###
