#!/bin/bash
# Cloudflare 优选 IP 流水线：测速 -> 生成订阅 -> 推送 GitHub（若已初始化仓库）
set -e
cd "$(dirname "$0")"

echo "[$(date '+%F %T')] 开始测速..."
python3 speedtest.py

echo "[$(date '+%F %T')] 生成订阅..."
python3 gen_sub.py

if [ -d .git ]; then
  git add -A
  if ! git diff --cached --quiet; then
    git commit -m "update $(date +%F)" --quiet
    git push --quiet && echo "[$(date '+%F %T')] 已推送到 GitHub"
  else
    echo "[$(date '+%F %T')] 无变化，跳过推送"
  fi
else
  echo "[$(date '+%F %T')] 未初始化 git 仓库，跳过推送（订阅文件已在本地生成）"
fi

echo "[$(date '+%F %T')] 完成"
