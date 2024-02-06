generate:
	docker build -f proto/Dockerfile --target proto-js -t wg-access-server-proto:js .
	docker build -f proto/Dockerfile --target proto-go -t wg-access-server-proto:go .
	docker run --rm -v `pwd`/proto:/proto -v `pwd`/website/src/sdk:/code/src/sdk wg-access-server-proto:js
	docker run --rm -v `pwd`/proto:/code/proto wg-access-server-proto:go

PRIVATE_KEY=`wg genkey`
dev:
	docker build . -t wg-access-server:dev
	docker run \
	-it \
	--rm \
	--cap-add NET_ADMIN \
	--cap-add SYS_MODULE \
	--device /dev/net/tun:/dev/net/tun \
	--sysctl net.ipv6.conf.all.disable_ipv6=0 \
	--sysctl net.ipv6.conf.all.forwarding=1 \
	-v wg-access-server-data:/data \
	-v /lib/modules:/lib/modules:ro \
	-e "WG_ADMIN_PASSWORD=password" \
	-e "WG_WIREGUARD_PRIVATE_KEY=${PRIVATE_KEY}" \
	-p 8000:8000/tcp \
	-p 51820:51820/udp \
	wg-access-server:dev
	
