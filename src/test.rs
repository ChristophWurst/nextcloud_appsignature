pub static PEM_PRIVATE_KEY: &'static str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDM8e7XeoNRhzGT
K/pXtXq4W52J62Yhsv6cldWP3GhiMIxp3jiKuKIbgQVR5XBYd9iAzHmsFz6KczwI
95zZkL66VTw/YyHKdxFpNw4Z7RfmN/xUKqRGhJzO8NouampSUFEDeUhSPW6Rb0mg
gTA/kkmZoBDR0QHJ5CotipJlMlTjpHLatkT/ygOYXh7OyfGVtBARXO+DM89QPcOi
odfmGdvRHIINkRJo2vY60nsZExgwbVeoJx6D2jRkN0jCd5nAl3HUDcPHtXJ6wtNe
/Z7i1uxMC4FYRBgfagkt2bALmdwtApYIq0uNjejMxQux7QyAdeuUWHrMop/yP1bH
sUhpbIWzAgMBAAECggEASdXjwZfu1aGKV8ZhU9YbF25STI0VZ5CwMEO/BCxZIv7w
p3ebEUdBh/0sqHurxQOwaX7BWyGos4Ken3Bt/ugp/sGUihWx59qL2EcwemCz2opT
CxOtyYYfZGLbiBtooK008rZwOsjNG/JnKT9B3bVbdNB5Hs5ZAZ6FH5Er+u9uK/C/
GdNvOfFy/pumZ4pymfFnZY6h/AbVxYgtyf4wXDFxiOsSctrAOgCF7fpbvCmMxDmX
utnnaulatZSLl3r1H/GgvjuDYjgBMzt1+/Ul6JZr9XUYB884o4dLfghKI/3FisrZ
l2FevnB4vb/73j7GboXebLxRYX712zYCRbfmgQpk4QKBgQDsuKngXePP/Td2e2hg
Na+RfM/c4cDyj6CM/yzGUMLnrWtvZC/kXYtv6uS93E4h6n0I8l7Xe+1BYDVt52hG
mHS8H6x3wP/MLA4UbYP+SKvnfVzRoCEM6jebF+mNKHGdMjeAC6JkcNjNeB2dyn+m
MB2mJ4MlKDCvcqS/dUcWjnLyUQKBgQDdosZDjFOMQ4bMBxWw8aROzFiDhoSinIf4
PRVkOFMmo7DGs1d0DmdH9oTiq6mTKkwqMCSQqenfyC0U6p+kOfwgBBGnIIKhr55+
so4hvPUuKV4fPsv8Oe+TVi5/+iennRQB+0+uPux6Ggr/zslTN5adlskPRvVKlgyS
ciCB4kBSwwKBgQDmnfTpn668Rz2MUSfbaxHzE/xRfSIDbUeFdWfCgJWRLVMYPyul
ODkKvHVCPmlkA1TyrWUWWyZF5ZvHyYS+GfLH/7d/J2hNGbJR1mucBGJs8KXHl0/7
jAbGMuKWYYtmELEfLrZzUbj1W4rG2avIVOHdqGrMfT4I/xBfcbriz75OMQKBgE+n
DTv/dZNGPW6b6TbDUTqkg/cY5BgQy2jygvqWp4OOdpyinX5vIr0hIpbX/MSQAflz
feCjwBKVvWX0AFWkJTFYZQO8UlZLaFm+UAheAXuKkHIIPoUySSCZa3LA83lwoV0o
9XT41kH3lBZlOcN3ieCu7SlZZhRdIr2K2JX1OwrDAoGAW+KZIQ1bJFHTzVuNvdeg
7hCeerVztyI8qI4dRUK2PW8RQlPrx9VvW6Zj4C4p7jcWuY+lO/4xWi4Mo++OMuTa
7w4fkY6tZxO/xzrJN/2IdeuxcKUWD8uz4nItSWhXkAQNfASzHBI1SGhhoabEj8LT
DthNb4qmH3Yc3OY3S98eO80=
-----END PRIVATE KEY-----";

#[allow(dead_code)]
pub static PEM_PUBLIC_KEY: &'static [u8] = b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzPHu13qDUYcxkyv6V7V6
uFudietmIbL+nJXVj9xoYjCMad44iriiG4EFUeVwWHfYgMx5rBc+inM8CPec2ZC+
ulU8P2MhyncRaTcOGe0X5jf8VCqkRoSczvDaLmpqUlBRA3lIUj1ukW9JoIEwP5JJ
maAQ0dEByeQqLYqSZTJU46Ry2rZE/8oDmF4ezsnxlbQQEVzvgzPPUD3DoqHX5hnb
0RyCDZESaNr2OtJ7GRMYMG1XqCceg9o0ZDdIwneZwJdx1A3Dx7VyesLTXv2e4tbs
TAuBWEQYH2oJLdmwC5ncLQKWCKtLjY3ozMULse0MgHXrlFh6zKKf8j9Wx7FIaWyF
swIDAQAB
-----END PUBLIC KEY-----";

pub static TEST_CONTENT: &'static [u8] = b"FOO";

pub static EXPECTED_SIGNATURE: &'static str = "Y64cx3UmfB0DVYO96e\
Ke5vYrVYDxXZXAJusSKEbh1JogjpMqKlzUlYMpZNkFAGMDUKkCo0QktyE5wH/v2/E\
QyRW5VxyU3UkC16vG7KgD4h9yskUNQGhbo7ux9B2aWwWhDCbr3UAJN/eHguR65nnG\
Tq4jszjcmndQqSNUQHg4PUSujrDrx/R2dW/yXO9o4yWRog1keFiXDt1sKgghzFaui\
TAXB/9xv+Z5fFixnHkpItSzJ9YH/P0gQqhom8ppsjdXqDw0lgjlZS7rmeeSjFCear\
C5Iu8cM72zwAkNRA2ewOzD4D6VUUrncq0x/hWSpGmOTrHae9tv/d2lKMvPtZPq1A==";

pub static PEM_PRIVATE_KEY_RSA: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzXhhhA/eeev0SmDkMqvmnKA/4Jnljkuiv9nUQ98K3IalpKh4
KPEcEluUVeNJpvFTsstYe4aBqXQIdCCxjfsvubuVOESZzOt0c1/y39X1FeK8oxa6
5+pmexGX2TnyAv3yZ/QTteaI8HwEc/NrMuYJUQUaPXCPOIWWUZfYHx3n8lRNE3Nt
1DCvUDpgMUqc0HZ3n4SMtRbW8kbw1AiAk9PyO55dKNMzaP09Ixi/W2Tb7qpsGfEU
BRtWtxo/UQVA7po7EnDmF6EWuI9BlYANJfCASSaNZd63K8VvuskxkSFcdg7262F8
S4Bed7mHDJODUgWIkh/9pDtdWZn84iJjEU9CgQIDAQABAoIBAQC7yBQfNL2X4cwe
mdSUdsRJSq92XlAMrxVrjvHOoa50gt4p0QoYKNsF8ApuQE4Us6NR2UPhiLlBm9kK
AMMkxncEoOosRY3mWR3RP9RhO1JFETZjOqfQwkmsmhSUI8AJefsrhEbrTGjEmCMd
sU68cr36/NXRZuiNuJD7uvF65sMPlNYCiLgf5y6hllx3dOp0hODd//bBEuEYYX2u
L9jBTajyBmos3tdhj6wA3BxehLK8kWkMFsmhBFD6Sz5BNRx6kTJgjxUffBMenYVl
aA6qnfN+S+tLAJV3RZkFuqRiB4REUl7ipkd8jPZyTPlfyS/8bqKoBL3HDjRGp8RD
3j6dTDJRAoGBAPLUAEJmL/a9kRoNzlJsrgVfI0l42nKRLGtRjDiZZDeJ8pKuB5fi
rVwIHnHbASq8/GJcfGThRZh2uNStYevRGxet7dS/K0i4eG3Amcvr5S7kW0+kI0UD
cv0YNURkJQK2HDkVrBIAyjILqyLxymHRf4IXR0o0QWUr421PqGaONI5tAoGBANid
nWDYZvBuxXC8TCSIJEiBpIEq4mqUefELWZV5+I50JKeGRF9Y4/RnuDTUFeFXV830
l85WesJqii5XhtelDo2eeMKHIgzaXfmQabBSXaEFH7nMDx+Hw3Ngm5o0AAMjoaOD
t4071NYVTVRIY27MHiIdG8WObyBsrf7rZd/cNmflAoGBAI+N9XlLoB9mglm8v7TK
uzZBwEK3R61jVbc8RoFPbYfH7bf5WlPYllRKGHWG23HAuBQOSRv6cYJo7WwN9E3N
GQ8uq+OSAKzFIa0Ap+t+UccfCTxT9OXf3CL0JMmByr+HmbfFsCwUe3SKoWnPN64M
hC0MRgEAU4jUIWeGKDA48akhAoGBAMhS+vhVKN2xk2ZuvPwL64IiYsARqNJn/V2t
4WsbIYKcZkmHIjQLQMUGJpS0joeW/ty5Fqr7zwt8+81fpJRJUOwnYgaEcjjwuXfS
1er6QRxoYK6yyEmghGBvN3ekH17H1PQjG9zBOFPD33/SciJFIpjp0oUg9CRIXaEi
kVQ1kxsBAoGAF3mIupnmb6fD7X4MH2w2zsfw7Fn7c8qOJdtY13nFYhaCboDXBBos
BSyoYC1erBejjf5/feDGBhWj005kLcCTGDuqZbC7MaGCvuHWc10ZCmmCUbbR8o4L
MxyF6eS0eJNvUqOkMezodZduTedGwEiv8w/Ltdfi1S/wkIJlLTrRc7M=
-----END RSA PRIVATE KEY-----
";

pub static EXPECTED_RSA_SIGNATURE: &'static str = "tQ6PDNPiHsaYED\
BNxC+jNTzpub8je6tlM1hSRFwbUfaimxM2y+EMTZ1UnAZtZ510tIxJL4Ku9PO8a8x\
mTu5EyaF/QNjSU2Tmy8G7ap3E0ANvZgA6B6UKEblUVtcr+N485QsrIfYmzwfo85Fr\
ZRefHZpM7fxrl1HT3bJRH895Vie+Y7qKUCSSZt4kc1jwPddRC3BQ9leiWBaZ/BOmZ\
XSbp+q3KtxUvCFQiuHZNfBm1ORJLYwHEszUz3Atms4Wr9vO6x0bD4cIJKqYkTfFKg\
7v/ToHp2tCXGhpg5SfO7IiE1BXSX2qwPY7O+vBOEaoO5WZL5TmVIukMFRqURDSfA2K2g==";
