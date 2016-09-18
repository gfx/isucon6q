#!/bin/bash
set -ex

if [ -f /var/log/nginx/access.log ]; then
    sudo mv /var/log/nginx/access.log /var/log/nginx/access.log.$(date "+%Y%m%d_%H%M%S")
fi
sudo systemctl restart mysql
sudo systemctl restart isuda.ruby.service
sudo systemctl restart isutar.ruby.service
sudo systemctl restart nginx