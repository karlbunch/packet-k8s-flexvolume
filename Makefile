.PHONY: test clean push unit-test

test:
	kubectl apply -f test-packet-volume-zfs.yaml

clean:
	kubectl delete -f test-packet-volume-zfs.yaml

push:
	set -x;for host in $$(kubectl get nodes -o jsonpath='{range.items[*]}{.metadata.name}{"\n"}{end}'); \
	do \
	    echo "Push to $$host"; \
	    ssh -q $$host 'logger -t fv_packet_zfs "#################### PUSHING ####################"'; \
	    scp -q /etc/kubernetes/packet-volume.conf $$host:/etc/kubernetes/packet-volume.conf; \
	    scp -q -r flexvolume $$host:/usr/libexec/kubernetes/kubelet-plugins/volume/exec/packet~flexvolume/; \
	done;

test-live:
	flexvolume/packet/test/test_live.py
