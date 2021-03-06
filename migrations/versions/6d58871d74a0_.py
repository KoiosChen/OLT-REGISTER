"""empty message

Revision ID: 6d58871d74a0
Revises: 112f84ac7d55
Create Date: 2016-07-25 14:26:11.928317

"""

# revision identifiers, used by Alembic.
revision = '6d58871d74a0'
down_revision = '112f84ac7d55'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('account', sa.Column('bas_name', sa.String(length=20), nullable=True))
    op.drop_index('ix_account_username', table_name='account')
    op.create_index(op.f('ix_account_username'), 'account', ['username'], unique=False)
    op.drop_column('mac_learned_by_ont', 'device_id')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('mac_learned_by_ont', sa.Column('device_id', mysql.VARCHAR(collation='utf8_bin', length=2), nullable=True))
    op.drop_index(op.f('ix_account_username'), table_name='account')
    op.create_index('ix_account_username', 'account', ['username'], unique=True)
    op.drop_column('account', 'bas_name')
    ### end Alembic commands ###
