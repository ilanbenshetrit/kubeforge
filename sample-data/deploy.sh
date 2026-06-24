#!/bin/bash
# Deployment script — contains hardcoded credentials (bad practice demo)
kubectl create secret generic db-secret \
  --from-literal=password=Prod@ssw0rd2026 \
  --from-literal=host=db.internal

export REDIS_URL="redis://:RedisPass123@cache.internal:6379"
echo "Deploying with password: Admin@12345"
