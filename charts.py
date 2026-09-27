import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT_DIR = "charts"
os.makedirs(OUT_DIR, exist_ok=True)

SCHEMES = ["PFCBPS", "[8]", "[5]", "[20]", "[9]", "[23]"]

# Table 3 (milliseconds)
DEL_GEN = [6.67, 6.67, 6.67, 20.01, 13.34, 13.34]
DEL_VER = [20.01, 26.68, 20.01, 73.37, 46.69, 46.69]
PROXY_SIGN = [6.67, 9.34, 9.34, 20.01, 20.01, 13.34]
PROXY_SVER = [13.34, 46.69, 40.02, 86.71, 86.71, 53.36]
TOTAL = [sum(v) for v in zip(DEL_GEN, DEL_VER, PROXY_SIGN, PROXY_SVER)]

# Table 4 (bits)
DELEGATION_BITS = [512, 768, 768, 512, 256, 256]
SIGNATURE_BITS = [512, 1280, 1536, 768, 512, 256]


def bar_chart(filename, values, ylabel, title):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar(SCHEMES, values, color="#4C72B0")
    ax.set_xlabel("Schemes Considered")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, filename), dpi=150)
    plt.close(fig)


bar_chart("fig6_delegation.png", DEL_GEN, "Time for delegation (msec.)", "Delegation Generation Time")
bar_chart("fig7_delegation_verify.png", DEL_VER, "Time for delegation verification (msec.)", "Delegation Verification Time")
bar_chart("fig8_proxy_signing.png", PROXY_SIGN, "Time for proxy signing (msec.)", "Proxy Signing Time")
bar_chart("fig9_sign_verify.png", PROXY_SVER, "Time for proxy signature verification (msec.)", "Proxy Signature Verification Time")
bar_chart("fig10_total.png", TOTAL, "Total computational time (msec.)", "Total Computational Cost")
bar_chart("fig11_delegation_bits.png", DELEGATION_BITS, "Delegation Length in bits", "Delegation Communication Cost")
bar_chart("fig12_signature_bits.png", SIGNATURE_BITS, "Signature Length in bits", "Proxy Signature Communication Cost")

print(f"wrote 7 charts to {os.path.abspath(OUT_DIR)}")
