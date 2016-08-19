#!/usr/bin/env bash

### https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-16-04

### !!! see comments for substitutions

sudo apt-get -y update
sudo apt-get -y upgrade


# Java 8
sudo add-apt-repository -y ppa:webupd8team/java
sudo apt-get -y update
echo debconf shared/accepted-oracle-license-v1-1 select true | sudo debconf-set-selections
echo debconf shared/accepted-oracle-license-v1-1 seen true | sudo debconf-set-selections
sudo apt-get -y install oracle-java8-installer


# Elasticsearch
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
sudo apt-get -y update
sudo apt-get -y install elasticsearch
sudo sed -i "s/# network.host: 192.168.0.1/network.host: localhost/" /etc/elasticsearch/elasticsearch.yml
sudo systemctl restart elasticsearch
sudo systemctl daemon-reload


# Kibana
echo "deb http://packages.elastic.co/kibana/4.5/debian stable main" | sudo tee -a /etc/apt/sources.list
sudo apt-get -y update
sudo apt-get -y install kibana
sudo sed -i "s/# server.host: \"0.0.0.0\"/server.host: \"localhost\"/" /opt/kibana/config/kibana.yml
sudo systemctl daemon-reload
sudo systemctl enable kibana
sudo systemctl start kibana


# Nginx
sudo apt-get -y install nginx
sudo -v
### !!! substitute password
echo "kibanaadmin:`openssl passwd -apr1 Wo3Pp7hAjw`" | sudo tee -a /etc/nginx/htpasswd.users
sudo tee /etc/nginx/sites-available/default <<EOF
server {
    listen 80;

    server_name example.com;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;        
    }
}
EOF
sudo nginx -t
sudo systemctl restart nginx
sudo ufw allow 'Nginx Full'

# Kibana is now accessible via your FQDN or the public IP address of your ELK Server with "kibanaadmin" credentials


# Logstash
echo "deb http://packages.elastic.co/logstash/2.3/debian stable main" | sudo tee -a /etc/apt/sources.list
sudo apt-get -y update
sudo apt-get -y install logstash
sudo mkdir -p /etc/pki/tls/certs
sudo mkdir /etc/pki/tls/private
### !!! substitute ip address
sudo sed -i '/\[ v3_ca \]/ a\subjectAltName = IP: 46.101.101.214' /etc/ssl/openssl.cnf
cd /etc/pki/tls
sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt
sudo tee /etc/logstash/conf.d/02-beats-input.conf <<EOF
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
EOF
sudo ufw allow 5044
sudo tee /etc/logstash/conf.d/10-syslog-filter.conf <<EOF
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOF
sudo tee /etc/logstash/conf.d/30-elasticsearch-output.conf <<EOF
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
EOF
sudo systemctl restart logstash
sudo systemctl enable logstash


# Kibana Dashboards
cd ~
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.2.2.zip
sudo apt-get -y install unzip
unzip beats-dashboards-*.zip
cd beats-dashboards-*
./load.sh