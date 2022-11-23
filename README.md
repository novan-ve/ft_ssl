# ft_ssl
Reimplementing cryptographic functions from the openssl library in C.

All calculations are done manually, without the use of external libraries.

Supported commands:
  - genrsa
  - rsa
  - rsautl

Message Digest commands:
  - md5
  - sha1
  - sha256

Cipher commands:
  - base64
  - des
  - des-ecb
  - des-cbc

## Usage

```bash
ft_ssl command [flags] [file/string]

ft_ssl genrsa [-i val] [-o outfile]
ft_ssl rsa [-inform PEM] [-outform PEM] [-in file] [-passin arg] [-out file] [-passout arg] [-des] [-text] [-noout] [-modulus] [-check] [-pubin] [-pubout]
ft_ssl rsautl [-in infile] [-out outfile] [-inkey val] [-pubin] [-encrypt] [-decrypt] [-hexdump]

ft_ssl md5 [-pqr] [-s text] [FILE]...
ft_ssl sha1 [-pqr] [-s text] [FILE]...
ft_ssl sha256 [-pqr] [-s text] [FILE]...

ft_ssl base64 [-d] [-e] [-i infile] [-o outfile]
ft_ssl des [-a] [-d] [-e] [-i infile] [-k val] [-o outfile] [-p val] [-s val] [-v val]
ft_ssl des-ecb [-a] [-d] [-e] [-i infile] [-k val] [-o outfile] [-p val] [-s val] [-v val]
ft_ssl des-cbc [-a] [-d] [-e] [-i infile] [-k val] [-o outfile] [-p val] [-s val] [-v val]
```
