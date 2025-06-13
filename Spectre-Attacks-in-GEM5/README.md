
All attacks were conducted in the system call emulation (SE) mode with the following configuration parameters:

```bash
GEM5FLAGS 		+=   configs/example/se.py \
					--num-cpus=1 \
					--bp-type=BiModeBP \
			 		--caches \
					--l2cache \
					--num-l2cache=1 \
			 		--l1i_size=32kB \
			 		--l1i_assoc=8 \
					--l1d_size=32kB \
			 		--l1d_assoc=8 \
					--l2_size=256kB \
					--l2_assoc=16 \
					--mem-size=8192MB \
					--cpu-type=DerivO3CPU \
```

