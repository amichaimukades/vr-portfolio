CFLAGS = -g -O0 -fno-stack-protector -no-pie
# NOTE: these binaries are deliberately vulnerable, for the exploitation lab only.

all: vuln vuln_gadget vuln_static vuln_leak

vuln: vuln.c
	gcc $(CFLAGS) -o $@ $<

vuln_gadget: vuln_gadget.c
	gcc $(CFLAGS) -o $@ $<

vuln_static: vuln.c
	gcc $(CFLAGS) -static -o $@ $<

vuln_leak: vuln_leak.c
	gcc $(CFLAGS) -o $@ $<

clean:
	rm -f vuln vuln_gadget vuln_static vuln_leak core core.*

.PHONY: all clean