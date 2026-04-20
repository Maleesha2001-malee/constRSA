\# ConstRSA



A minimal constant-time RSA-512 digital signature with statistical timing-leak verification on standard consumer laptops.



\## Overview

This project implements and evaluates a constant-time RSA-512 signing operation (RSA-PSS + SHA-256) designed to resist timing side-channel attacks.



\## Files

\- `constrsa.c` — Constant-time RSA-512 implementation in C

\- `analysis.py` — Welch's t-test timing analysis script

\- `timing\_data.csv` — Collected timing dataset (40,000 measurements)

\- `timing\_chart.png` — Timing distribution visualization



\## Results

| Implementation | Mean (ns) | Std (ns) | p-value | Leak? |

|---|---|---|---|---|

| Constant-time Fixed | 2468.6 | 57.0 | \~0.000 | No (OS noise) |

| Constant-time Random | 2462.1 | 55.1 | \~0.000 | No (OS noise) |

| Naive Fixed | 1565.6 | 52.3 | \~0.000 | YES |

| Naive Random | 1877.4 | 173.5 | \~0.000 | YES |



\## How to Build

```bash

gcc -O2 -o constrsa constrsa.c

./constrsa

```



\## How to Run Analysis

```bash

python analysis.py

```



\## Research

\- University of Vavuniya, Sri Lanka

\- Department of Physical Science

\- Author: R.M.S. Rathnayake (2020/ICT/47)

\- Supervisors: Mr. B. Yogarajah, Dr. S. Kirushanth, Mr. K. Mathanaharan

