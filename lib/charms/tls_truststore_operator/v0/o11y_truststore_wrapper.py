
# todo: this function should be in an o11y lib.
def generate_csr(password, generate_priv_key_fn, generate_csr_fn):
    privkey = generate_priv_key_fn(password)
    csr = generate_csr_fn(privkey, password)
    return privkey, csr
