#!/usr/bin/env bash

sudo apt-get -y update
sudo apt-get -y upgrade
sudo apt-get -y install build-essential tcl
cd /tmp
curl -O http://download.redis.io/redis-stable.tar.gz
tar xzvf redis-stable.tar.gz
cd redis-stable
make
sudo make install
sudo mkdir /etc/redis
sudo cp /tmp/redis-stable/redis.conf /etc/redis
sudo sed -i "s/supervised no/supervised systemd/" /etc/redis/redis.conf
sudo sed -i "s/dir \.\//dir \/var\/lib\/redis/" /etc/redis/redis.conf

sudo tee /etc/systemd/system/redis.service <<EOF
[Unit]
Description=Redis In-Memory Data Store
After=network.target

[Service]
User=redis
Group=redis
ExecStart=/usr/local/bin/redis-server /etc/redis/redis.conf
ExecStop=/usr/local/bin/redis-cli shutdown
Restart=always

[Install]
WantedBy=multi-user.target   
EOF

sudo adduser --system --group --no-create-home redis
sudo mkdir /var/lib/redis
sudo chown redis:redis /var/lib/redis
sudo chmod 770 /var/lib/redis

sudo systemctl start redis

sudo systemctl enable redis

## check status:
# sudo systemctl status redis

## connect to the Redis server with the command-line client:
# redis-cli

## restart the Redis instance:
# sudo systemctl restart redis