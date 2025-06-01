The **SSL Recognition** is a comprehensive, modular utility built in Python, specifically tailored for evaluating the security and configuration of SSL/TLS certificates used by websites. Designed to run seamlessly on Android devices using Termux without requiring root access, this tool allows security researchers, developers, and penetration testers to gain deep insights into SSL implementations directly from their mobile environments. Each module within the tool performs a specific task related to SSL inspection, ensuring clarity, maintainability, and focused functionality. 

The first module, **ssl_chain.py**, acts as a certificate inspector. It retrieves the SSL certificate chain for a given domain and provides detailed insights such as the issuer and subject fields, serial number, certificate version, and signature algorithm. It also computes the certificate's SHA-256 fingerprint and calculates how many days remain before the certificate expires.

The second module, **ssl_expiry.py**, is dedicated to monitoring the expiry status of SSL certificates. It fetches the certificate from the specified domain, parses the expiration date, and determines how many days are left until the certificate becomes invalid. It also provides additional metadata such as the subject, issuer, serial number, and validity period in days. This module is particularly useful for sysadmins and developers who need to manage certificate renewals and avoid unexpected service disruptions proactively.

The third module, **ssl_pining.py**, focuses on SSL pinning and transport security. It extracts the certificate fingerprint using the SHA-256 algorithm, which can be used for SSL pinning implementation checks in mobile apps or web applications. Additionally, it verifies whether the domain has enabled HTTP Strict Transport Security (HSTS), a critical header that enforces secure connections and mitigates downgrade attacks. This module supports batch processing of multiple domains through concurrent threads, improving efficiency and scalability.

The fourth module, **ssl_report.py**, integrates with the public API of Qualys SSL Labs, one of the most trusted platforms for SSL configuration testing. This module retrieves detailed reports including the server’s SSL grade, supported protocol versions (e.g., TLS 1.2, TLS 1.3), enabled cipher suites, server signature, and security features like OCSP stapling and HSTS. It also flags critical vulnerabilities such as BEAST, POODLE, Heartbleed, and RC4 usage. 

The output is structured in a clean table format, making it easy to interpret important certificate metadata.



![Screenshot 2025-06-01 185851](https://github.com/user-attachments/assets/4796ea32-1491-4503-91b3-fc562a2d82b9)


