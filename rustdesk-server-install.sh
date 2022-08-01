sudo docker image pull rustdesk/rustdesk-server
sudo docker run -td --name hbbs -p 21115:21115 -p 21116:21116 -p 21116:21116/udp -p 21118:21118 -v `pwd`:/root -it --net=host --rm rustdesk/rustdesk-server:latest hbbs -r ip/dns:port
sudo docker run -td --name hbbr -p 21117:21117 -p 21119:21119 -v `pwd`:/root -it --net=host --rm rustdesk/rustdesk-server:latest hbbr 
ufw allow 21115
ufw allow 21116
ufw allow 21117
ufw allow 21118
ufw allow 21119
