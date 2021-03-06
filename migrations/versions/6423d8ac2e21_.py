"""empty message

Revision ID: 6423d8ac2e21
Revises: b668f3526768
Create Date: 2016-08-07 16:00:58.497938

"""

# revision identifiers, used by Alembic.
revision = '6423d8ac2e21'
down_revision = 'b668f3526768'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('service_port', sa.Column('cevlan_range', sa.String(length=12), nullable=False))
    op.add_column('service_port', sa.Column('outvlan', sa.String(length=5), nullable=False))
    op.create_index(op.f('ix_service_port_cevlan_range'), 'service_port', ['cevlan_range'], unique=False)
    op.create_index(op.f('ix_service_port_outvlan'), 'service_port', ['outvlan'], unique=False)
    op.drop_index('ix_service_port_vlan_range', table_name='service_port')
    op.drop_column('service_port', 'vlan_range')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('service_port', sa.Column('vlan_range', mysql.VARCHAR(collation='utf8_bin', length=12), nullable=False))
    op.create_index('ix_service_port_vlan_range', 'service_port', ['vlan_range'], unique=False)
    op.drop_index(op.f('ix_service_port_outvlan'), table_name='service_port')
    op.drop_index(op.f('ix_service_port_cevlan_range'), table_name='service_port')
    op.drop_column('service_port', 'outvlan')
    op.drop_column('service_port', 'cevlan_range')
    ### end Alembic commands ###
