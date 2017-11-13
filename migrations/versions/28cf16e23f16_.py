"""empty message

Revision ID: 28cf16e23f16
Revises: 96a73b0d9b98
Create Date: 2017-01-17 11:08:10.067037

"""

# revision identifiers, used by Alembic.
revision = '28cf16e23f16'
down_revision = '96a73b0d9b98'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('call_time_range',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('range_name', sa.String(length=100), nullable=True),
    sa.Column('start_time', sa.Time(), nullable=False),
    sa.Column('stop_time', sa.Time(), nullable=False),
    sa.Column('status', sa.SmallInteger(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('job_desc',
    sa.Column('job_id', sa.String(length=5), nullable=False),
    sa.Column('job_name', sa.String(length=20), nullable=True),
    sa.Column('job_desc', sa.String(length=100), nullable=True),
    sa.PrimaryKeyConstraint('job_id')
    )
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('job_desc')
    op.drop_table('call_time_range')
    ### end Alembic commands ###
