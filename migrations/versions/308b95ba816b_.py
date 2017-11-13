"""empty message

Revision ID: 308b95ba816b
Revises: 35ac08982fff
Create Date: 2016-12-05 17:12:12.744042

"""

# revision identifiers, used by Alembic.
revision = '308b95ba816b'
down_revision = '35ac08982fff'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_index(op.f('ix_alarm_record_content'), 'alarm_record', ['content'], unique=False)
    op.create_index(op.f('ix_alarm_record_content_md5'), 'alarm_record', ['content_md5'], unique=False)
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_alarm_record_content_md5'), table_name='alarm_record')
    op.drop_index(op.f('ix_alarm_record_content'), table_name='alarm_record')
    ### end Alembic commands ###
