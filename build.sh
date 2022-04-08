image=registry.kubeup.cn/kube/libvirt-exporter:v1.2.1
docker build -t $image .
docker push $image