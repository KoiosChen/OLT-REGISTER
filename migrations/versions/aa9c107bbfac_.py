"""empty message

Revision ID: aa9c107bbfac
Revises: d2e0a94031d7
Create Date: 2016-08-15 00:32:56.857529

"""

# revision identifiers, used by Alembic.
revision = 'aa9c107bbfac'
down_revision = 'd2e0a94031d7'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('permit_machine_room', sa.String(length=200), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'permit_machine_room')
    ### end Alembic commands ###
