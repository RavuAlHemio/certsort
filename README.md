# certsort

X.509 certificate sorter.

Takes one or more PEM or DER files and outputs a series of PEM structures
representing the same data in the requested order.

PEM files may contain multiple kinds of structures; DER files may only contain
one or more certificates.

The default output order is:

1. The host certificate.

2. The intermediate certificate that issued the host certificate.

3. The intermediate certificate that issued the intermediate
   certificate in step 2.

4. etc.

5. The root certificate.

6. The private key.

7. Any other PEM structure (e.g. Diffie-Hellman parameters).

This order tends to make most software the happiest. It can be changed
using the `-O`/`--order` command line option.

No guarantee is made about the output order if the user supplies certificates
from more than one certificate chain.
