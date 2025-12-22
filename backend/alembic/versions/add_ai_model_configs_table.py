"""add ai_model_configs table

Revision ID: 001_add_ai_model_configs
Revises:
Create Date: 2024-12-21 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_ai_model_configs'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create ai_model_configs table
    op.create_table(
        'ai_model_configs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False, comment='模型名称'),
        sa.Column('display_name', sa.String(length=200), nullable=False, comment='显示名称'),
        sa.Column('description', sa.Text(), nullable=True, comment='模型描述'),
        sa.Column('model_type', sa.String(length=20), nullable=False, comment='模型类型：transcription/text_generation'),
        sa.Column('api_url', sa.String(length=500), nullable=False, comment='API端点URL'),
        sa.Column('api_key', sa.String(length=500), nullable=False, comment='API密钥（加密存储）'),
        sa.Column('api_key_encrypted', sa.Boolean(), nullable=True, default=True, comment='API密钥是否加密'),
        sa.Column('model_id', sa.String(length=200), nullable=False, comment='模型标识符'),
        sa.Column('provider', sa.String(length=100), nullable=False, default='custom', comment='提供商：openai/siliconflow/custom等'),
        sa.Column('max_tokens', sa.Integer(), nullable=True, comment='最大令牌数'),
        sa.Column('temperature', sa.String(length=10), nullable=True, comment='温度参数'),
        sa.Column('timeout_seconds', sa.Integer(), nullable=True, default=300, comment='请求超时时间（秒）'),
        sa.Column('max_retries', sa.Integer(), nullable=True, default=3, comment='最大重试次数'),
        sa.Column('max_concurrent_requests', sa.Integer(), nullable=True, default=1, comment='最大并发请求数'),
        sa.Column('rate_limit_per_minute', sa.Integer(), nullable=True, default=60, comment='每分钟请求限制'),
        sa.Column('cost_per_input_token', sa.String(length=20), nullable=True, comment='每输入令牌成本'),
        sa.Column('cost_per_output_token', sa.String(length=20), nullable=True, comment='每输出令牌成本'),
        sa.Column('extra_config', sa.JSON(), nullable=True, default=dict, comment='额外配置参数'),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True, comment='是否启用'),
        sa.Column('is_default', sa.Boolean(), nullable=True, default=False, comment='是否为默认模型'),
        sa.Column('is_system', sa.Boolean(), nullable=True, default=False, comment='是否为系统预设模型'),
        sa.Column('usage_count', sa.Integer(), nullable=True, default=0, comment='使用次数'),
        sa.Column('success_count', sa.Integer(), nullable=True, default=0, comment='成功次数'),
        sa.Column('error_count', sa.Integer(), nullable=True, default=0, comment='错误次数'),
        sa.Column('total_tokens_used', sa.Integer(), nullable=True, default=0, comment='总令牌使用数'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True, comment='创建时间'),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True, comment='更新时间'),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True, comment='最后使用时间'),
        sa.PrimaryKeyConstraint('id'),
        comment='AI模型配置表'
    )

    # Create indexes
    op.create_index('ix_ai_model_configs_name', 'ai_model_configs', ['name'], unique=False)
    op.create_index('idx_model_type_active', 'ai_model_configs', ['model_type', 'is_active'], unique=False)
    op.create_index('idx_model_type_default', 'ai_model_configs', ['model_type', 'is_default'], unique=False)
    op.create_index('idx_provider_model', 'ai_model_configs', ['provider', 'model_id'], unique=False)


def downgrade() -> None:
    # Drop indexes
    op.drop_index('idx_provider_model', table_name='ai_model_configs')
    op.drop_index('idx_model_type_default', table_name='ai_model_configs')
    op.drop_index('idx_model_type_active', table_name='ai_model_configs')
    op.drop_index('ix_ai_model_configs_name', table_name='ai_model_configs')

    # Drop table
    op.drop_table('ai_model_configs')