# \# ConstRSA

# 

# > Design and Statistical Validation of a Minimal Constant-Time RSA-512 Digital Signature on Standard Consumer Laptops

# 

# \*\*Author:\*\* R.M.S. Rathnayake (2020/ICT/47)  

# \*\*University:\*\* University of Vavuniya, Sri Lanka  

# \*\*Supervisors:\*\* Mr. B. Yogarajah, Dr. S. Kirushanth, Mr. K. Mathanaharan

# 

# \---

# 

# \## Research Aim

# 

# To design, implement, and statistically validate a minimal constant-time RSA-512 digital signature (RSA-PSS with SHA-256) suitable for testing on standard consumer laptops.

# 

# \## Algorithm

# 

# \- Constant-time modular exponentiation (square-and-multiply-always)

# \- Branchless selection via arithmetic masking

# \- CRT optimization for signing

# \- Welch's t-test for timing-leak verification

# 

# \## Constant-time Design

# 

# No secret-dependent branches. No secret-dependent memory access. Result selection uses bitwise masking instead of if-statements.

# 

\## Repository Structure

constrsa/
===

# ├── src/

# │   └── constrsa.c       # RSA implementation

# ├── tests/

# │   └── analysis.py      # Welch's t-test analysis

# ├── data/

# │   └── timing\_data.csv  # Timing measurements

# ├── docs/

# │   └── timing\_chart.png # Results visualization

└── README.md

## How to Build and Run
===

# 

# ```bash

# gcc -O2 -o constrsa src/constrsa.c

# ./constrsa

# ```

# 

# \## How to Run Analysis

# 

# ```bash

# python tests/analysis.py

# ```

# 

# \## Results

# 

# | Implementation | Mean (ns) | p-value | Leak? |

# |---|---|---|---|

# | Constant-time Fixed  | 2468.6 | \~0.000 | No (OS noise) |

# | Constant-time Random | 2462.1 | \~0.000 | No (OS noise) |

# | Naive Fixed          | 1565.6 | \~0.000 | YES |

# | Naive Random         | 1877.4 | \~0.000 | YES |

# 

# \## Files Produced

# 

# \- `data/timing\_data.csv` — 40,000 timing measurements

# \- `docs/timing\_chart.png` — Distribution histogramss

