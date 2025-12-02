# Redis Stack Config
# You can change the Redis URL according to your environment
# Login in Redis Insight by http://192.168.241.128:8001 and default/redis-stack-password-for-agentic-soc-platform
# 根据你的环境修改Redis的连接地址
# 通过 http://192.168.241.128:8001 和 default/redis-stack-password-for-agentic-soc-platform 登录 Redis Insight
REDIS_URL = "redis://:redis-stack-password-for-agentic-soc-platform@192.168.241.128:6379/"
REDIS_STREAM_STORE_DAYS = 7  # 消息在Redis Stream中保存的天数

# API TOKEN
# Use this token to access the REST API
# SIRP 使用此 Token 访问 REST API, 需要在SIRP中配置相同的Token
# headers = {"Authorization": "Token nocoly_token_for_playbook"}
ASF_TOKEN = "nocoly_token_for_playbook"
