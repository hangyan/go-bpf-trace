# go-bpf-trace
goalng ebpf trace packet example

This project use libbpf and libbpfgo. The result go binary will use CGO.



## Build

```bash
make flowsnoop-static
```


## Known issues:

1. need BTF to run


## Test Cases
1. In container
2. Different kernel versions



## Links
1. [Tracee Install](https://aquasecurity.github.io/tracee/dev/install/prerequisites/)
