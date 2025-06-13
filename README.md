### Source PoC for Speculative Cache Side-Channel Attacks
This repository contains the proof-of-concept (PoC) implementations used in the security evaluation of the paper "SCSGuardian: Fine-Grained Protection Against Speculative Cache Side-Channel Attacks."
We provide PoC attacks adapted to three representative execution environments, covering both simulation and hardware platforms.
```bash
├── Spectre-Attacks-in-GEM5/         # x86 PoC adapted to gem5 simulator
├── Spectre-Attacks-in-Chipyard/     # RISC-V PoC adapted to Chipyard simulation
├── Spectre-Attacks-in-SonicBoom/    # RISC-V PoC running on FPGA hardware (SonicBOOM)
```