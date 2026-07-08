#!/usr/bin/env bash
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:5000/health && exit 0
  sleep 1
done
exit 1
