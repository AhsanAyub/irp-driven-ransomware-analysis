## I/O Request Packet Driven Ransomware Analysis
This purpose of this project is to perform an exahaustive ransomware analysis through I/O Request Packet (IRP), low-level file system I/O logs. We aim to achieve the followings goals:

* `Time Series Analysis`: Detection of the ransomware process early enough to claim real-time detection;
* `Heuristic Approach / Fuzzy Technique`: Derive threshold value(s) of features space over time for the ransomware IRP logs compared with benign logs;
* `Sequence Mining / Pattern Mining`: Devise an automated sequence from different ransomware samples that would aid early detection provided a sequence is matched for a given process; and
* `Machine Learning (Multiclass Classification)`: Detection of the ransomware families from the ransomware IRP logs.


### Acknowledgement

We would like to thank [Andrea Continella, Ph.D.](https://conand.me/) to provide us with the datasets that we have used on this project. The research paper can be found here: [SheildFS 2016](https://dl.acm.org/doi/pdf/10.1145/2991079.2991110).
