"""empty message

Revision ID: d2e0a94031d7
Revises: 9e8d840c836e
Create Date: 2016-08-15 00:26:36.680168

"""

# revision identifiers, used by Alembic.
revision = 'd2e0a94031d7'
down_revision = '9e8d840c836e'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('machineroom_list', sa.Column('permit_value', sa.String(length=200), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('machineroom_list', 'permit_value')
    ### end Alembic commands ###
