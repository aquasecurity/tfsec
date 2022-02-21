---
title: The Kubernetes cluster does not enable surge upgrades
---

# The Kubernetes cluster does not enable surge upgrades

### Default Severity: <span class="severity medium">medium</span>

### Explanation

While upgrading your cluster, workloads will temporarily be moved to new nodes. A small cost will follow, but as a bonus, you won't experience downtime.

### Possible Impact
Upgrades may influence availability of your Kubernetes cluster

### Suggested Resolution
Enable surge upgrades in your Kubernetes cluster


### Insecure Example

The following example will fail the digitalocean-compute-surge-upgrades-not-enabled check.
```terraform

resource "digitalocean_kubernetes_cluster" "surge_upgrade_bad" {
	name   = "foo"
	region = "nyc1"
	version = "1.20.2-do.0"
	surge_upgrade = false
	
	node_pool {
		name       = "worker-pool"
		size       = "s-2vcpu-2gb"
		node_count = 3
	
		taint {
			key    = "workloadKind"
			value  = "database"
			effect = "NoSchedule"
		}
	}
}
 
```



### Secure Example

The following example will pass the digitalocean-compute-surge-upgrades-not-enabled check.
```terraform

resource "digitalocean_kubernetes_cluster" "surge_upgrade_good" {
	name   = "foo"
	region = "nyc1"
	version = "1.20.2-do.0"
	surge_upgrade = true

	node_pool {
		name       = "worker-pool"
		size       = "s-2vcpu-2gb"
		node_count = 3
	
		taint {
			key    = "workloadKind"
			value  = "database"
			effect = "NoSchedule"
		}
	}
}
 
```



### Links


- [https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#surge_upgrade](https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#surge_upgrade){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.digitalocean.com/products/kubernetes/how-to/upgrade-cluster/#surge-upgrades](https://docs.digitalocean.com/products/kubernetes/how-to/upgrade-cluster/#surge-upgrades){:target="_blank" rel="nofollow noreferrer noopener"}



