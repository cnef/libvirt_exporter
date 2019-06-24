image=registry-local.kubeup.cn/ekos/libvirt-exporter:v1.2
docker build -t $image .
docker push $image