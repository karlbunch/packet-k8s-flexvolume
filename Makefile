.PHONY: test clean push unit-test

test:
	kubectl apply -f test-packet-volume-zfs.yaml

clean:
	kubectl delete -f test-packet-volume-zfs.yaml

push:
	set -x;\
	rm -fr stage; \
	mkdir -p stage/lib; \
	cp -ar flexvolume stage/lib; \
	cp -ar packet-python/packet stage/lib; \
	cp plugin stage/flexvolume; \
	for host in $$(kubectl get nodes -o jsonpath='{range.items[*]}{.metadata.name}{"\n"}{end}'); \
	do \
	    echo "Push to $$host"; \
	    ssh $$host 'logger -t fv_packet_zfs "#################### PUSHING packet~flexvolume ####################"'; \
	    scp -q flexvolume-packet.conf $$host:/etc/kubernetes/flexvolume-packet.conf; \
	    scp -q -r stage/. $$host:/usr/libexec/kubernetes/kubelet-plugins/volume/exec/packet~flexvolume/; \
	done;

test-live:
	flexvolume/packet/test/test_live.py

check:
	pylint --reports=n flexvolume
