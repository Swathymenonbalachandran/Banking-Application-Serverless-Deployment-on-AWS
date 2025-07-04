"""Initial migration

Revision ID: a49ba411bdec
Revises: 
Create Date: 2023-11-11 14:40:54.260811

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a49ba411bdec'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('deposit',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('account_number', sa.String(length=20), nullable=False),
    sa.Column('account_holder', sa.String(length=80), nullable=False),
    sa.Column('deposit_amount', sa.String(length=20), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('account')
    op.drop_table('account_type')
    op.drop_table('user_account')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('account_number',
               existing_type=sa.VARCHAR(length=120),
               type_=sa.String(length=20),
               existing_nullable=False)
        batch_op.alter_column('contact',
               existing_type=sa.VARCHAR(length=12),
               type_=sa.String(length=20),
               existing_nullable=False)
        batch_op.create_unique_constraint(None, ['contact'])
        batch_op.create_unique_constraint(None, ['account_number'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_constraint(None, type_='unique')
        batch_op.alter_column('contact',
               existing_type=sa.String(length=20),
               type_=sa.VARCHAR(length=12),
               existing_nullable=False)
        batch_op.alter_column('account_number',
               existing_type=sa.String(length=20),
               type_=sa.VARCHAR(length=120),
               existing_nullable=False)

    op.create_table('user_account',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('account_holder', sa.VARCHAR(length=80), nullable=False),
    sa.Column('initial_balance', sa.VARCHAR(length=120), nullable=False),
    sa.Column('currentbalance', sa.VARCHAR(length=120), nullable=False),
    sa.Column('address', sa.VARCHAR(length=200), nullable=False),
    sa.Column('contact', sa.VARCHAR(length=20), nullable=False),
    sa.Column('passport_number', sa.VARCHAR(length=20), nullable=False),
    sa.Column('account_type', sa.VARCHAR(length=50), nullable=False),
    sa.Column('account_number', sa.VARCHAR(length=20), nullable=False),
    sa.Column('created_at', sa.DATETIME(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('account_number')
    )
    op.create_table('account_type',
    sa.Column('account_id', sa.INTEGER(), nullable=False),
    sa.Column('account_name', sa.VARCHAR(length=50), nullable=False),
    sa.Column('account_description', sa.VARCHAR(length=200), nullable=True),
    sa.PrimaryKeyConstraint('account_id'),
    sa.UniqueConstraint('account_name')
    )
    op.create_table('account',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('type', sa.VARCHAR(length=80), nullable=False),
    sa.Column('description', sa.VARCHAR(length=200), nullable=True),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('deposit')
    # ### end Alembic commands ###
