# Benchmark Comparison Report

Generated: 2026-03-09 16:02:45

| Benchmark | TS avg (ms) | Rust avg (ms) | Speedup | Status |
|-----------|-------------|---------------|---------|--------|
| BigNumber mul large | 0.7828 | 1.7686 | 0.4x | **SLOWER** |
| BigNumber add large | 30.0818 | 1.1270 | 26.7x | OK |
| BN toSm big | 0.7966 | N/A | N/A | Rust N/A |
| BN toSm little | 0.8473 | N/A | N/A | Rust N/A |
| BN fromSm big | 0.7052 | N/A | N/A | Rust N/A |
| BN fromSm little | 0.7393 | N/A | N/A | Rust N/A |
| BN fromScriptNum | 0.7361 | 0.0397 | 18.5x | OK |
| ECC Point.mul WNAF | 0.3623 | N/A | N/A | Rust N/A |
| ECC Point.mulCT | 0.7387 | N/A | N/A | Rust N/A |
| ECDSA sign | 0.8141 | 0.4806 | 1.7x | OK |
| ECDSA verify | 1.5379 | 1.1407 | 1.3x | OK |
| Script findAndDelete 4000 chunks 10% | N/A | N/A | N/A | - |
| Script findAndDelete 8000 chunks 5% | 0.2536 | N/A | N/A | Rust N/A |
| Script findAndDelete 8000 chunks 20% | 0.6981 | N/A | N/A | Rust N/A |
| Script findAndDelete 2000 chunks 300B | 0.0671 | N/A | N/A | Rust N/A |
| Script findAndDelete 12000 chunks 1% | 0.2229 | N/A | N/A | Rust N/A |
| Script serialization round trip | 1.5847 | N/A | N/A | Rust N/A |
| SymmetricKey encrypt large 2MB | 849.4002 | 131.9713 | 6.4x | OK |
| SymmetricKey decrypt large 2MB | 823.6411 | 130.7514 | 6.3x | OK |
| SymmetricKey encrypt 50 small | 3.6439 | 0.6370 | 5.7x | OK |
| SymmetricKey decrypt 50 small | 3.4863 | 0.4613 | 7.6x | OK |
| SymmetricKey encrypt 200 medium | 88.1460 | 14.1732 | 6.2x | OK |
| SymmetricKey decrypt 200 medium | 85.4414 | 13.5905 | 6.3x | OK |
| Transaction deep chain verify | 176.0855 | N/A | N/A | Rust N/A |
| Transaction wide verify | 183.4866 | N/A | N/A | Rust N/A |
| Transaction large verify | 91.3650 | N/A | N/A | Rust N/A |
| Transaction nested verify | 51.8053 | N/A | N/A | Rust N/A |
| Atomic BEEF serialize | 0.6432 | 0.1107 | 5.8x | OK |
| Atomic BEEF deserialize | 1.2814 | 0.9852 | 1.3x | OK |
| Reader/Writer mixed ops | 0.0970 | 0.0360 | 2.7x | OK |
| Reader/Writer large payloads | 17.1340 | N/A | N/A | Rust N/A |
| Reader/Writer 3000 small | 0.6016 | N/A | N/A | Rust N/A |
| Reader/Writer 400 medium | 8.6814 | N/A | N/A | Rust N/A |
| SHA-256 32B | 0.0015 | 0.0002 | 8.5x | OK |
| SHA-256 1KB | 0.0059 | 0.0028 | 2.1x | OK |
| SHA-256 1MB | 4.9084 | 2.6586 | 1.8x | OK |
| SHA-512 32B | 0.0027 | 0.0003 | 10.5x | OK |
| SHA-512 1KB | 0.0118 | 0.0020 | 5.8x | OK |
| SHA-512 1MB | 9.7900 | 1.8160 | 5.4x | OK |
| RIPEMD-160 32B | 0.0007 | 0.0002 | 3.2x | OK |
| RIPEMD-160 1KB | 0.0075 | 0.0033 | 2.3x | OK |
| RIPEMD-160 1MB | 7.7856 | 3.1565 | 2.5x | OK |
| HMAC-SHA256 1KB | 0.0074 | 0.0033 | 2.2x | OK |
| HMAC-SHA512 1KB | 0.0160 | 0.0027 | 5.9x | OK |
| ECIES Electrum encrypt 32B | 0.0185 | 0.0111 | 1.7x | OK |
| ECIES Electrum encrypt 1KB | 0.0731 | 0.0184 | 4.0x | OK |
| ECIES Electrum encrypt 64KB | 4.5145 | 0.5016 | 9.0x | OK |
| ECIES Electrum decrypt 32B | 0.0336 | 0.0673 | 0.5x | **SLOWER** |
| ECIES Electrum decrypt 1KB | 0.0869 | 0.0798 | 1.1x | OK |
| ECIES Electrum decrypt 64KB | 4.2368 | 0.9087 | 4.7x | OK |
| ECIES Bitcore encrypt 32B | 0.0190 | 0.0118 | 1.6x | OK |
| ECIES Bitcore encrypt 1KB | 0.0879 | 0.0209 | 4.2x | OK |
| ECIES Bitcore encrypt 64KB | 5.4265 | 0.6299 | 8.6x | OK |
| ECIES Bitcore decrypt 32B | 0.0930 | 0.0682 | 1.4x | OK |
| ECIES Bitcore decrypt 1KB | 0.1593 | 0.0862 | 1.8x | OK |
| ECIES Bitcore decrypt 64KB | 5.0487 | 1.2142 | 4.2x | OK |

## Summary

- **Total mappings:** 56
- **Matched (both sides):** 37
- **TS only:** 18
- **Rust only:** 0
- **Rust slower than TS:** 2 (flagged with **SLOWER**)
