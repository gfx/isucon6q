#!/bin/bash
set -ex

sudo cat /var/log/nginx/access.log | /home/isucon/kataribe/kataribe -f /home/isucon/kataribe/kataribe.toml
