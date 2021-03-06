"""empty message

Revision ID: e4669e6d52d6
Revises: 68dfa6cfefec
Create Date: 2016-12-04 07:59:32.329478

"""

# revision identifiers, used by Alembic.
revision = 'e4669e6d52d6'
down_revision = '68dfa6cfefec'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('phoneNum', sa.String(length=15), nullable=True))
    op.create_unique_constraint(None, 'users', ['phoneNum'])
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.drop_column('users', 'phoneNum')
    ### end Alembic commands ###
