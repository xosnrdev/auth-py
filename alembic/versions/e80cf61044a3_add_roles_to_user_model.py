"""add roles to user model

Revision ID: e80cf61044a3
Revises: 0bce084d4400
Create Date: 2025-02-22 11:14:04.126823

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e80cf61044a3'
down_revision: Union[str, None] = '0bce084d4400'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('roles', postgresql.JSONB(astext_type=sa.Text()), server_default='["user"]', nullable=False, comment='User roles for RBAC (e.g., user, admin)'))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'roles')
    # ### end Alembic commands ###
