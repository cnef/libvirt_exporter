# Prometheus libvirt exporter

This repository provides code for a Prometheus metrics exporter
for [libvirt](https://libvirt.org/). This exporter connects to any
libvirt daemon and exports per-domain metrics related to CPU, memory,
disk and network usage. By default, this exporter listens on TCP port
9177.

This exporter makes use of
[libvirt-go](https://github.com/libvirt/libvirt-go), the official Go
bindings for libvirt. Ideally, this exporter should make use of the
`GetAllDomainStats()` API call to extract all relevant metrics.
Unfortunately, we at Kumina still need this exporter to be compatible
with older versions of libvirt that don't support this API call.

The following metrics/labels are being exported:

```
libvirt_domain_block_stats_read_bytes_total{domain="...",source_file="...",target_device="..."}
libvirt_domain_block_stats_read_requests_total{domain="...",source_file="...",target_device="..."}
libvirt_domain_block_stats_write_bytes_total{domain="...",source_file="...",target_device="..."}
libvirt_domain_block_stats_write_requests_total{domain="...",source_file="...",target_device="..."}
libvirt_domain_info_cpu_time_seconds_total{domain="..."}
libvirt_domain_info_maximum_memory_bytes{domain="..."}
libvirt_domain_info_memory_usage_bytes{domain="..."}
libvirt_domain_info_virtual_cpus{domain="..."}
libvirt_domain_interface_stats_receive_bytes_total{domain="...",source_bridge="...",target_device="..."}
libvirt_domain_interface_stats_receive_drops_total{domain="...",source_bridge="...",target_device="..."}
libvirt_domain_interface_stats_receive_errors_total{domain="...",source_bridge="...",target_device="..."}
libvirt_domain_interface_stats_receive_packets_total{domain="...",source_bridge="...",target_device="..."}
libvirt_domain_interface_stats_transmit_bytes_total{domain="...",source_bridge="...",target_device="..."}
libvirt_domain_interface_stats_transmit_drops_total{domain="...",source_bridge="...",target_device="..."}
libvirt_domain_interface_stats_transmit_errors_total{domain="...",source_bridge="...",target_device="..."}
libvirt_domain_interface_stats_transmit_packets_total{domain="...",source_bridge="...",target_device="..."}
libvirt_up
```

At Kumina we want to perform a single build of this exporter, deploying
it to a variety of Linux distribution versions. This is why this
repository contains a shell script, `build_static.sh`, that builds a
statically linked copy of this exporter in an Alpine Linux based
container.


## libvirt metrics

referrer:

- https://www.cnblogs.com/ruiy/p/6297106.html
- https://yunlzheng.gitbook.io/prometheus-book/part-iii-prometheus-shi-zhan/readmd/use-prometheus-monitor-kubernetes

domain.info()返回列表参数说明：

[State:1, Max memory:2097152L, Used memory:2097152L, CPU(s):2, CPU time:4245630000000L]

domain.blockInfo(device)返回结果说明：

[capacity:42949672960L, allocation:2233990656L, physical:2300968960L]

domain.memoryStats()返回结果说明：

{'swap_out': 0L, 'available': 1884432L, 'actual': 2097152L, 'major_fault': 457L, 'swap_in': 0L, 'unused': 1367032L, 'minor_fault': 1210349717L, 'rss': 743604L}

 其中actual是启动虚机时设置的最大内存，rss是qemu process在宿主机上所占用的内存，unused代表虚机内部未使用的内存量，available代表虚机内部识别出的总内存量，那么虚机内部的内存使用量则是可以通过(available-unused)得到。

需要安装virtio驱动才会获得完整数据

**Max memory:**

Retrieve the maximum amount of physical memory allocated to a domain. If domain is NULL, then this get the amount of memory reserved to Domain0 i.e. the domain where the application runs.

the memory size in kibibytes (blocks of 1024 bytes), or 0 in case of error.

~~~json
libvirt_domain_info_cpu_time_seconds_total{domain="..."}  = CpuTime
libvirt_domain_info_maximum_memory_bytes{domain="..."}    = MaxMem
libvirt_domain_info_memory_usage_bytes{domain="..."}      = Memory
libvirt_domain_info_virtual_cpus{domain="..."}            = NrVirtCpu
~~~