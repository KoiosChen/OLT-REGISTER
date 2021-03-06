"""empty message

Revision ID: 0fd42a67381a
Revises: 42cd4c9116ff
Create Date: 2016-12-06 21:58:34.619528

"""

# revision identifiers, used by Alembic.
revision = '0fd42a67381a'
down_revision = '42cd4c9116ff'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('call_record_detail', sa.Column('create_time', sa.DateTime(), nullable=True))
    op.drop_column('call_record_detail', 'createDate')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('call_record_detail', sa.Column('createDate', mysql.DATETIME(), nullable=True))
    op.drop_column('call_record_detail', 'create_time')
    ### end Alembic commands ###
